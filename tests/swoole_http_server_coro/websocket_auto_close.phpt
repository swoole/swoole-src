--TEST--
swoole_http_server_coro: automatically close TCP after replying to a WebSocket Close frame
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/Assert.php';

use Swoole\Coroutine;
use Swoole\Coroutine\Channel;
use Swoole\Coroutine\Http\Client;
use Swoole\Coroutine\Http\Server;
use Swoole\WebSocket\CloseFrame;
use SwooleTest\Assert;

Assert::setThrowException(true);
Coroutine\run(function () {
    foreach (defined('SWOOLE_SSL') ? [false, true] : [false] as $tls) {
        $server = new Server('127.0.0.1', 0, $tls);
        if ($tls) {
            $server->set([
                'ssl_cert_file' => __DIR__ . '/../include/ssl_certs/server.crt',
                'ssl_key_file' => __DIR__ . '/../include/ssl_certs/server.key',
            ]);
        }
        $finished = new Channel(1);
        $release = new Channel(1);
        $server->handle('/', function ($request, $response) use ($finished, $release) {
            Assert::true($response->upgrade());
            $finished->push([$response->recv(5)]);
            // Keep the handler alive so only the automatic Close path can produce the TCP EOF.
            $release->pop(5);
        });
        Coroutine::create(fn () => $server->start());
        $client = new Client('127.0.0.1', $server->port, $tls);
        $client->set(['timeout' => 2, 'open_websocket_close_frame' => true]);
        try {
            foreach (['', str_repeat('r', 123)] as $reason) {
                Assert::true($client->upgrade('/'));
                $close = new CloseFrame();
                $close->code = SWOOLE_WEBSOCKET_CLOSE_NORMAL;
                $close->reason = $reason;
                Assert::true($client->push($close));
                $reply = $client->recv();
                Assert::isInstanceOf($reply, CloseFrame::class);
                Assert::same($reply->code, $close->code);
                Assert::same($reply->reason, $reason);
                $eof = $client->recv();
                if ($tls && $eof === false) {
                    // Closing a TLS socket without close_notify is reported as SSL reset instead of EOF.
                    Assert::same($client->errCode, SWOOLE_ERROR_SSL_RESET);
                } else {
                    Assert::same($eof, '');
                }
                Assert::false($client->connected);
                Assert::same($finished->pop(2), ['']);
                Assert::true($release->push(true));
            }
        } finally {
            $release->close();
            $client->close();
            $server->shutdown();
        }
    }
});
echo "DONE\n";
?>
--EXPECT--
DONE
