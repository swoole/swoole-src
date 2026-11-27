--TEST--
swoole_http_client_coro/websocket: incomplete messages are scoped to the current connection
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/Assert.php';

use Swoole\Coroutine;
use Swoole\Coroutine\Channel;
use Swoole\Coroutine\Http\Client;
use Swoole\Coroutine\Http\Server;
use Swoole\WebSocket\Frame;
use SwooleTest\Assert;

Assert::setThrowException(true);
Coroutine\run(function () {
    $server = new Server('127.0.0.1', 0);
    $resume = new Channel(1);
    $server->handle('/', function ($request, $response) use ($resume) {
        Assert::true($response->upgrade());
        $path = $request->server['request_uri'];
        if ($path === '/fresh') {
            Assert::true($response->push('fresh'));
            return;
        }

        Assert::true($response->push('first', SWOOLE_WEBSOCKET_OPCODE_TEXT, 0));
        if ($path === '/eof') {
            $response->close();
            return;
        }
        Assert::true($response->push('ready', SWOOLE_WEBSOCKET_OPCODE_PING));
        if ($path === '/continue') {
            if ($resume->pop(5)) {
                Assert::true($response->push('last', SWOOLE_WEBSOCKET_OPCODE_CONTINUATION));
            }
        } else {
            $response->recv(5);
        }
    });
    Coroutine::create(fn () => $server->start());

    $client = new Client('127.0.0.1', $server->port);
    $client->set(['timeout' => 2, 'open_websocket_ping_frame' => true]);
    try {
        foreach (['/eof', '/close', '/socket-close'] as $path) {
            Assert::true($client->upgrade($path));
            if ($path === '/eof') {
                Assert::same($client->recv(), '');
            } else {
                $ping = $client->recv();
                Assert::isInstanceOf($ping, Frame::class);
                Assert::same($ping->opcode, SWOOLE_WEBSOCKET_OPCODE_PING);
                Assert::true($path === '/close' ? $client->close() : $client->socket->close());
            }
            Assert::false($client->connected);

            Assert::true($client->upgrade('/fresh'));
            $frame = $client->recv();
            Assert::isInstanceOf($frame, Frame::class);
            Assert::same($frame->data, 'fresh');
            $client->close();
        }

        Assert::true($client->upgrade('/continue'));
        $ping = $client->recv();
        Assert::isInstanceOf($ping, Frame::class);
        Assert::same($ping->opcode, SWOOLE_WEBSOCKET_OPCODE_PING);
        Assert::false($client->recv(0.05));
        Assert::same($client->errCode, SOCKET_ETIMEDOUT);
        Assert::true($resume->push(true));
        $frame = $client->recv();
        Assert::isInstanceOf($frame, Frame::class);
        Assert::same($frame->data, 'firstlast');
    } finally {
        $resume->close();
        $client->close();
        $server->shutdown();
    }
});
echo "DONE\n";
?>
--EXPECT--
DONE
