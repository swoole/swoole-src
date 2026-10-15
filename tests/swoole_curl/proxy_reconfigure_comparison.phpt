--TEST--
swoole_curl: PHP and native hooks remove and replace proxies on a reused handle
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_extension_not_exist('curl');
?>
--FILE--
<?php
use Swoole\Coroutine;
use Swoole\Coroutine\Http\Server;

require __DIR__ . '/../include/curl_hook_comparison.inc';
run_curl_hook_comparison(function () {
    $servers = [];
    foreach (['origin', 'proxy-1', 'proxy-2'] as $body) {
        $server = new Server('127.0.0.1', 0);
        $server->handle('/', fn ($request, $response) => $response->end($body));
        Coroutine::create(fn () => $server->start());
        $servers[] = $server;
    }
    $ch = curl_init('http://127.0.0.1:' . $servers[0]->port . '/');
    curl_setopt_array($ch, [CURLOPT_PROXY => '', CURLOPT_NOPROXY => '', CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => 2]);
    try {
        foreach ([
            [CURLOPT_PROXY, 'http://127.0.0.1:' . $servers[1]->port, 'proxy-1'],
            [CURLOPT_PROXY, '', 'origin'],
            [CURLOPT_PROXY, 'http://127.0.0.1:' . $servers[2]->port, 'proxy-2'],
            [CURLOPT_PROXY, '', 'origin'],
        ] as [$option, $value, $expected]) {
            curl_setopt($ch, $option, $value);
            if (curl_exec($ch) !== $expected || curl_errno($ch) !== CURLE_OK) {
                throw new RuntimeException('Proxy configuration was not replaced');
            }
        }
        curl_setopt_array($ch, [CURLOPT_PROXY => '127.0.0.1', CURLOPT_PROXYPORT => $servers[1]->port]);
        if (curl_exec($ch) !== 'proxy-1') {
            throw new RuntimeException('Explicit proxy port was ignored');
        }
        curl_setopt($ch, CURLOPT_PROXYPORT, $servers[2]->port);
        if (curl_exec($ch) !== 'proxy-2') {
            throw new RuntimeException('Changed proxy port reused the old connection');
        }
        curl_close($ch);
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
