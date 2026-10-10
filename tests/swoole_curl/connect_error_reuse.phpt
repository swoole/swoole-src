--TEST--
swoole_curl: PHP hook maps refused connections to CURLE_COULDNT_CONNECT and clears errors on reuse
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_extension_not_exist('curl');
?>
--FILE--
<?php
use Swoole\Coroutine;
use Swoole\Coroutine\Http\Server;
use Swoole\Coroutine\Socket;
use Swoole\Curl\Handler;

Swoole\Runtime::enableCoroutine(SWOOLE_HOOK_CURL);
Coroutine\run(function () {
    // Reserve a port without listening so that connections are refused deterministically.
    $reserved = new Socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
    if (!$reserved->bind('127.0.0.1', 0)) {
        throw new RuntimeException('Cannot reserve a port');
    }
    $refusedUrl = 'http://127.0.0.1:' . $reserved->getsockname()['port'] . '/';
    $server = new Server('127.0.0.1', 0);
    $server->handle('/', fn ($request, $response) => $response->end('OK'));
    Coroutine::create(fn () => $server->start());
    $goodUrl = 'http://127.0.0.1:' . $server->port . '/';
    $ch = curl_init($refusedUrl);
    if (!$ch instanceof Handler) {
        throw new RuntimeException('Expected the PHP curl hook');
    }
    curl_setopt_array($ch, [CURLOPT_PROXY => '', CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => 2]);
    try {
        for ($i = 0; $i < 2; $i++) {
            curl_setopt($ch, CURLOPT_URL, $refusedUrl);
            if (curl_exec($ch) !== false || curl_errno($ch) !== CURLE_COULDNT_CONNECT
                || curl_error($ch) === '' || curl_getinfo($ch, CURLINFO_RESPONSE_CODE) !== 0) {
                throw new RuntimeException('Unexpected connection error: ' . var_export([curl_errno($ch), curl_error($ch)], true));
            }
            curl_setopt($ch, CURLOPT_URL, $goodUrl);
            if (curl_exec($ch) !== 'OK' || curl_errno($ch) !== CURLE_OK || curl_error($ch) !== ''
                || curl_getinfo($ch, CURLINFO_RESPONSE_CODE) !== 200) {
                throw new RuntimeException('Connection error survived a successful request');
            }
        }
        curl_close($ch);
    } finally {
        $reserved->close();
        $server->shutdown();
    }
});
echo "DONE\n";
?>
--EXPECT--
DONE
