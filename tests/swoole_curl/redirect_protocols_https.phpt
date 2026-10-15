--TEST--
swoole_curl: PHP hook intersects redirect protocols and filters credentials across schemes
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_extension_not_exist('curl');
skip_if_no_ssl();
?>
--FILE--
<?php
use Swoole\Coroutine;
use Swoole\Coroutine\Http\Server;
use Swoole\Curl\Handler;

Swoole\Runtime::enableCoroutine(SWOOLE_HOOK_CURL);
Coroutine\run(function () {
    $servers = [new Server('127.0.0.1', 0), new Server('127.0.0.1', 0, true)];
    $servers[1]->set([
        'ssl_cert_file' => __DIR__ . '/../include/ssl_certs/server.crt',
        'ssl_key_file' => __DIR__ . '/../include/ssl_certs/server.key',
    ]);
    $requests = [0, 0];
    foreach ($servers as $index => $server) {
        $server->handle('/', function ($request, $response) use (&$requests, $index) {
            $requests[$index]++;
            if (isset($request->get['to'])) {
                $response->status(302);
                $response->header('Location', $request->get['to']);
            }
            $response->end(json_encode([
                $request->header['authorization'] ?? '',
                http_build_query($request->cookie ?? [], '', '; '),
            ]));
        });
        Coroutine::create(fn () => $server->start());
    }

    $http = 'http://127.0.0.1:' . $servers[0]->port . '/';
    $https = 'https://127.0.0.1:' . $servers[1]->port . '/';
    $auth = 'Basic ' . base64_encode('user:secret');
    $request = function ($url, $options, $expected, $counts) use (&$requests) {
        $ch = curl_init($url);
        if (!$ch instanceof Handler) {
            throw new RuntimeException('Expected the PHP curl hook');
        }
        curl_setopt_array($ch, $options + [
            CURLOPT_PROXY => '',
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_MAXREDIRS => 5,
            CURLOPT_TIMEOUT => 5,
            CURLOPT_SSL_VERIFYPEER => false,
            CURLOPT_SSL_VERIFYHOST => 0,
            CURLOPT_USERPWD => 'user:secret',
            CURLOPT_HTTPHEADER => ['Cookie: token=secret'],
        ]);
        $before = $requests;
        $body = curl_exec($ch);
        $errno = $expected === false ? CURLE_UNSUPPORTED_PROTOCOL : CURLE_OK;
        $actual = $body === false ? false : json_decode($body, true);
        $actualCounts = [$requests[0] - $before[0], $requests[1] - $before[1]];
        if ($actual !== $expected || curl_errno($ch) !== $errno || $actualCounts !== $counts) {
            throw new RuntimeException('Unexpected HTTPS result: ' . var_export([$actual, curl_errno($ch), $actualCounts], true));
        }
    };

    try {
        $request($https, [CURLOPT_PROTOCOLS => CURLPROTO_HTTPS], [$auth, 'token=secret'], [0, 1]);
        $request($https . '?to=' . urlencode($https), [CURLOPT_REDIR_PROTOCOLS => CURLPROTO_HTTPS], [$auth, 'token=secret'], [0, 2]);
        $request($https . '?to=' . urlencode('//127.0.0.1:' . $servers[1]->port . '/'), [
            CURLOPT_PROTOCOLS => CURLPROTO_HTTPS,
            CURLOPT_REDIR_PROTOCOLS => CURLPROTO_HTTPS,
        ], [$auth, 'token=secret'], [0, 2]);
        $request($https . '?to=' . urlencode($http), [], ['', ''], [1, 1]);
        $request($http . '?to=' . urlencode($https), [CURLOPT_REDIR_PROTOCOLS => CURLPROTO_HTTPS], ['', ''], [1, 1]);
        $request($https . '?to=' . urlencode($http), [CURLOPT_REDIR_PROTOCOLS => CURLPROTO_HTTPS], false, [0, 1]);
        $request($https . '?to=' . urlencode($http), [
            CURLOPT_PROTOCOLS => CURLPROTO_HTTPS,
            CURLOPT_REDIR_PROTOCOLS => CURLPROTO_HTTP | CURLPROTO_HTTPS,
        ], false, [0, 1]);
        $request($http . '?to=' . urlencode($https), [
            CURLOPT_PROTOCOLS => CURLPROTO_HTTP,
            CURLOPT_REDIR_PROTOCOLS => CURLPROTO_HTTP | CURLPROTO_HTTPS,
        ], false, [1, 0]);
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
