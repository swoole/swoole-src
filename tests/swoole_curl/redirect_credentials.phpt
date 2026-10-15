--TEST--
swoole_curl: PHP hook limits redirect credentials to the original URL origin
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_extension_not_exist('curl');
?>
--FILE--
<?php
use Swoole\Coroutine;
use Swoole\Coroutine\Http\Server;
use Swoole\Curl\Handler;

Swoole\Runtime::enableCoroutine(SWOOLE_HOOK_CURL);
Coroutine\run(function () {
    $servers = [new Server('127.0.0.1', 0), new Server('127.0.0.1', 0)];
    $requests = [];
    foreach ($servers as $server) {
        $server->handle('/', function ($request, $response) use (&$requests) {
            $headers = [
                $request->header['authorization'] ?? '',
                http_build_query($request->cookie ?? [], '', '; '),
                $request->header['x-test'] ?? '',
            ];
            $requests[] = $headers;
            if (isset($request->get['to'])) {
                $response->status(302);
                $response->header('Location', $request->get['to']);
            }
            $response->end(json_encode($headers));
        });
        Coroutine::create(fn () => $server->start());
    }

    $origin = 'http://127.0.0.1:' . $servers[0]->port;
    $other = 'http://127.0.0.1:' . $servers[1]->port;
    $auth = 'Basic ' . base64_encode('user:secret');
    $options = [
        CURLOPT_PROXY => '',
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_MAXREDIRS => 5,
        CURLOPT_TIMEOUT => 5,
        CURLOPT_USERPWD => 'user:secret',
        CURLOPT_HTTPHEADER => ['cOoKiE: token=secret', 'X-Test: retained'],
    ];
    $request = function ($url, $expected, $extra = []) use ($options) {
        $ch = curl_init($url);
        if (!$ch instanceof Handler) {
            throw new RuntimeException('Expected the PHP curl hook');
        }
        curl_setopt_array($ch, $extra + $options);
        $body = curl_exec($ch);
        if ($body === false || json_decode($body, true) !== $expected) {
            throw new RuntimeException('Unexpected credentials: ' . var_export($body, true));
        }
        return $ch;
    };

    try {
        $request($origin . '/?to=' . urlencode($origin . '/'), [$auth, 'token=secret', 'retained']);
        $ch = $request($origin . '/?to=' . urlencode($other . '/'), ['', '', 'retained']);
        // Reusing the redirected handle must not grant the foreign target credentials.
        if (json_decode(curl_exec($ch), true) !== ['', '', 'retained']) {
            throw new RuntimeException('Credentials leaked on handle reuse');
        }
        curl_setopt($ch, CURLOPT_URL, $origin . '/');
        if (json_decode(curl_exec($ch), true) !== [$auth, 'token=secret', 'retained']) {
            throw new RuntimeException('Redirect filtering changed configured headers');
        }
        $request($origin . '/?to=' . urlencode('http://localhost:' . $servers[0]->port . '/'), ['', '', 'retained']);
        $request($origin . '/?to=' . urlencode($other . '/'), ['', '', 'retained'], [
            CURLOPT_HTTPHEADER => ['aUtHoRiZaTiOn: Bearer secret', 'Cookie: token=secret', 'X-Test: retained'],
        ]);

        $requests = [];
        $request($origin . '/?to=' . urlencode($other . '/?to=' . urlencode($origin . '/')), [$auth, 'token=secret', 'retained']);
        if ($requests !== [[$auth, 'token=secret', 'retained'], ['', '', 'retained'], [$auth, 'token=secret', 'retained']]) {
            throw new RuntimeException('Credentials were not scoped per redirect hop');
        }

        // CURLOPT_RESOLVE changes the connection address, not the URL origin.
        $local = 'http://localhost:' . $servers[0]->port;
        $request($local . '/?to=' . urlencode('http://LOCALHOST:' . $servers[0]->port . '/'), [$auth, 'token=secret', 'retained'], [
            CURLOPT_RESOLVE => ['localhost:' . $servers[0]->port . ':127.0.0.1'],
        ]);

        // CURLOPT_COOKIE deliberately applies to all redirect targets, unlike a custom Cookie header.
        $request($origin . '/?to=' . urlencode($other . '/'), ['', 'option=secret', 'retained'], [
            CURLOPT_COOKIE => 'option=secret',
            CURLOPT_HTTPHEADER => ['X-Test: retained'],
        ]);
    } finally {
        foreach ($servers as $server) {
            $server->shutdown();
        }
    }
});
echo "DONE\n";
?>
--EXPECT--
DONE
