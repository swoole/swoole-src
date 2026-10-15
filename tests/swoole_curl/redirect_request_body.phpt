--TEST--
swoole_curl: PHP hook drops POST bodies on GET redirects and preserves resend bodies
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
            $data = [$request->server['request_method'], $request->getContent(), $request->header['content-type'] ?? ''];
            $requests[] = $data;
            if (isset($request->get['to'])) {
                $response->status((int) $request->get['code']);
                $response->header('Location', $request->get['to']);
            }
            $response->end(json_encode($data));
        });
        Coroutine::create(fn () => $server->start());
    }
    $origin = 'http://127.0.0.1:' . $servers[0]->port . '/';
    $other = 'http://127.0.0.1:' . $servers[1]->port . '/';
    $form = 'application/x-www-form-urlencoded';
    $request = function ($code, $target, $extra, $expected, $first = null) use ($origin, $form, &$requests) {
        $url = $origin . '?code=' . $code . '&to=' . urlencode($target);
        $ch = curl_init($url);
        if (!$ch instanceof Handler) {
            throw new RuntimeException('Expected the PHP curl hook');
        }
        curl_setopt_array($ch, $extra + [
            CURLOPT_PROXY => '',
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_MAXREDIRS => 5,
            CURLOPT_TIMEOUT => 5,
            CURLOPT_POSTFIELDS => 'payload',
        ]);
        $requests = [];
        $response = curl_exec($ch);
        $actual = $response === false ? false : json_decode($response, true);
        $expectedRequests = [$first ?? ['POST', 'payload', $form], $expected];
        if ($actual !== $expected || $requests !== $expectedRequests) {
            throw new RuntimeException('Unexpected redirect body: ' . var_export([$actual, $requests, $expectedRequests], true));
        }
        return $ch;
    };

    try {
        foreach ([$origin, $other] as $target) {
            foreach ([301, 302, 303] as $code) {
                $request($code, $target, [], ['GET', '', '']);
            }
            foreach ([307, 308] as $code) {
                $request($code, $target, [], ['POST', 'payload', $form]);
            }
        }
        $ch = $request(302, $origin, [], ['GET', '', '']);
        // A redirect changes this transfer, not the handle's configured POST mode or fields.
        curl_setopt($ch, CURLOPT_URL, $origin);
        $response = curl_exec($ch);
        if ($response === false || json_decode($response, true) !== ['POST', 'payload', $form]) {
            throw new RuntimeException('Redirect changed the configured POST request');
        }

        $request(302, $origin, [CURLOPT_CUSTOMREQUEST => 'PATCH'], ['PATCH', '', ''], ['PATCH', 'payload', $form]);
        $request(307, $other, [CURLOPT_CUSTOMREQUEST => 'PATCH'], ['PATCH', 'payload', $form], ['PATCH', 'payload', $form]);

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
