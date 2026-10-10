--TEST--
swoole_curl: PHP hook includes a redirected TLS handshake in the total timeout
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
use Swoole\Coroutine\Socket;
use Swoole\Curl\Handler;

Swoole\Runtime::enableCoroutine(SWOOLE_HOOK_CURL);
Coroutine\run(function () {
    // Accept TCP but never complete TLS, so a receive-only HTTP timeout cannot stop the handshake.
    $listener = new Socket(AF_INET, SOCK_STREAM, 0);
    $listener->bind('127.0.0.1', 0);
    $listener->listen();
    $tlsPort = $listener->getsockname()['port'];
    $peer = null;
    $accepted = false;
    Coroutine::create(function () use ($listener, &$peer, &$accepted) {
        $peer = $listener->accept(5);
        if ($peer) {
            $accepted = true;
            // Consume ClientHello and wait for the timed-out client to close the connection.
            while ($peer->recv(8192, 5) !== '') {
                if ($peer->errCode) {
                    break;
                }
            }
            $peer->close();
        }
    });
    $server = new Server('127.0.0.1', 0);
    $server->handle('/', function ($request, $response) use ($tlsPort) {
        Coroutine::sleep(0.08);
        $response->status(302);
        $response->header('Location', 'https://localhost:' . $tlsPort . '/');
        $response->end('redirect');
    });
    Coroutine::create(fn () => $server->start());
    try {
        $ch = curl_init('http://127.0.0.1:' . $server->port . '/');
        if (!$ch instanceof Handler) {
            throw new RuntimeException('Expected the PHP curl hook');
        }
        curl_setopt_array($ch, [CURLOPT_PROXY => '', CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => true, CURLOPT_TIMEOUT_MS => 250, CURLOPT_CONNECTTIMEOUT => 2,
            CURLOPT_RESOLVE => ['localhost:' . $tlsPort . ':127.0.0.2,127.0.0.1'],
            CURLOPT_SSL_VERIFYPEER => false, CURLOPT_SSL_VERIFYHOST => 0]);
        $start = hrtime(true);
        $body = curl_exec($ch);
        $elapsed = (hrtime(true) - $start) / 1e9;
        if ($body !== false || curl_errno($ch) !== CURLE_OPERATION_TIMEDOUT
            || !$accepted || curl_getinfo($ch, CURLINFO_REDIRECT_COUNT) !== 1
            || curl_getinfo($ch, CURLINFO_RESPONSE_CODE) !== 302
            || $elapsed < 0.15 || $elapsed > 0.9) {
            throw new RuntimeException('Redirected TLS handshake exceeded the total timeout: ' . var_export([$body, curl_errno($ch), $elapsed, $accepted], true));
        }
    } finally {
        $server->shutdown();
        $listener->close();
    }
});
echo "DONE\n";
?>
--EXPECT--
DONE
