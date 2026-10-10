--TEST--
swoole_curl: PHP hook defaults to HTTP proxies and preserves hostname proxy configuration
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
    $proxy = new Server('127.0.0.1', 0);
    $proxy->handle('/', function ($request, $response) {
        $target = explode(' ', $request->getData(), 3)[1];
        if (parse_url($target, PHP_URL_PATH) === '/redirect') {
            $response->status(302);
            $response->header('Location', '/final?0');
        }
        $response->end(json_encode([$target, $request->header['proxy-authorization'] ?? '']));
    });
    Coroutine::create(fn () => $proxy->start());
    $url = 'http://192.0.2.1:18080/path?0';
    $auth = 'Basic ' . base64_encode('user:secret');
    $cases = [
        [CURLOPT_PROXY => '127.0.0.1:' . $proxy->port],
        [CURLOPT_PROXY => 'localhost:' . $proxy->port],
        [CURLOPT_PROXY => 'http://localhost:' . $proxy->port],
        [CURLOPT_PROXY => 'localhost', CURLOPT_PROXYPORT => $proxy->port],
        [CURLOPT_PROXY => '127.0.0.1:' . $proxy->port, CURLOPT_PROXYTYPE => CURLPROXY_HTTP],
        [CURLOPT_PROXY => 'http://user:secret@localhost:' . $proxy->port],
        [CURLOPT_PROXY => 'localhost:' . $proxy->port, CURLOPT_PROXYUSERPWD => 'user:secret'],
    ];
    try {
        foreach ($cases as $index => $options) {
            $ch = curl_init($url);
            if (!$ch instanceof Handler) {
                throw new RuntimeException('Expected the PHP curl hook');
            }
            curl_setopt_array($ch, $options + [CURLOPT_RETURNTRANSFER => true,
                CURLOPT_NOPROXY => '', CURLOPT_TIMEOUT => 5]);
            // Reuse and redirects must not lose the configured proxy port or credentials after DNS.
            for ($i = 0; $i < 2; $i++) {
                $body = curl_exec($ch);
                $expected = [$url, $index >= 5 ? $auth : ''];
                if ($body === false || json_decode($body, true) !== $expected) {
                    throw new RuntimeException('Proxy request failed: ' . var_export([$options, $body, curl_error($ch)], true));
                }
            }
            curl_setopt_array($ch, [CURLOPT_URL => 'http://192.0.2.1:18080/redirect', CURLOPT_FOLLOWLOCATION => true]);
            $body = curl_exec($ch);
            if ($body === false || json_decode($body, true) !== ['http://192.0.2.1:18080/final?0', $index >= 5 ? $auth : '']) {
                throw new RuntimeException('Redirect lost the proxy configuration');
            }
            curl_reset($ch);
            curl_setopt_array($ch, [CURLOPT_URL => $url, CURLOPT_PROXY => '127.0.0.1:' . $proxy->port,
                CURLOPT_RETURNTRANSFER => true, CURLOPT_NOPROXY => '', CURLOPT_TIMEOUT => 5]);
            if (json_decode(curl_exec($ch), true) !== [$url, '']) {
                throw new RuntimeException('Reset did not restore the default HTTP proxy type');
            }
        }
    } finally {
        $proxy->shutdown();
    }
});
echo "DONE\n";
?>
--EXPECT--
DONE
