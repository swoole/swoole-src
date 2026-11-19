--TEST--
swoole_http_client_coro/websocket: timed receives keep the connection usable (#6417)
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

use Swoole\Coroutine;
use Swoole\Coroutine\Channel;
use Swoole\Coroutine\Http\Client;
use Swoole\Coroutine\Http\Server;
use Swoole\Http\Request;
use Swoole\Http\Response;
use Swoole\WebSocket\Frame;

Assert::setThrowException(true);

Coroutine\run(function () {
    $server = new Server('127.0.0.1', 0, false);
    $done = new Channel(1);
    $reply = new Channel(1);
    $server->handle('/ws', function (Request $request, Response $response) use ($done, $reply) {
        try {
            Assert::true($response->upgrade());
            while ($frame = $response->recv(-1)) {
                if ($frame->data === 'concurrent timeout' && !$reply->pop(5)) {
                    break;
                }
                Assert::true($response->push('echo:' . $frame->data));
            }
        } finally {
            $done->push(true);
        }
    });

    Coroutine::create(function () use ($server, $done, $reply) {
        $client = new Client('127.0.0.1', $server->port, false);
        $client->set(['timeout' => 5]);
        try {
            Assert::true($client->upgrade('/ws'));
            // The server sends nothing until a client frame arrives. Each explicit timeout is shorter
            // than the socket timeout, exercising recv_packet()'s outer timer on IOCP as well.
            for ($i = 0; $i < 3; $i++) {
                Assert::false($client->recv(0.05));
                Assert::same($client->errCode, SOCKET_ETIMEDOUT);
                Assert::true($client->connected);
            }

            Assert::true($client->push('after timeouts'));
            $frame = $client->recv(5);
            Assert::isInstanceOf($frame, Frame::class);
            Assert::same($frame->data, 'echo:after timeouts');
            Assert::true($client->connected);

            // A successful push shares this socket with the pending timed receive.
            // Withhold the echo until the receive times out.
            $timedOut = new Channel(1);
            Coroutine::create(function () use ($client, $timedOut) {
                Assert::false($client->recv(0.1));
                $timedOut->push([$client->errCode, $client->connected]);
            });
            Assert::true($client->push('concurrent timeout'));
            Assert::same($timedOut->pop(5), [SOCKET_ETIMEDOUT, true]);
            Assert::true($reply->push(true));
            $frame = $client->recv(5);
            Assert::isInstanceOf($frame, Frame::class);
            Assert::same($frame->data, 'echo:concurrent timeout');

            // Starting this coroutine suspends it in recv() before the other coroutine pushes.
            $received = new Channel(1);
            Coroutine::create(function () use ($client, $received) {
                $frame = $client->recv(-1);
                Assert::isInstanceOf($frame, Frame::class);
                $received->push($frame->data);
            });
            Assert::true($client->push('concurrent push'));
            Assert::same($received->pop(5), 'echo:concurrent push');
            Assert::true($client->connected);
        } finally {
            $reply->close();
            $client->close();
            Assert::true($done->pop(5));
            $server->shutdown();
        }
    });

    $server->start();
});
echo "DONE\n";
?>
--EXPECT--
DONE
