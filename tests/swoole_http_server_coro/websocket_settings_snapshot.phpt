--TEST--
swoole_http_server_coro: preserve WebSocket frame settings for each request
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

Swoole\Coroutine\run(function () {
    foreach ([true, false] as $openPing) {
        $server = new Swoole\Coroutine\Http\Server('127.0.0.1', 0);
        $server->set(['open_websocket_ping_frame' => $openPing]);
        $server->handle('/', function ($request, $response) use ($server, $openPing) {
            // set() updates PHP settings; the active accept loop keeps its startup options.
            $server->set(['open_websocket_ping_frame' => !$openPing]);
            Assert::true($response->upgrade());
            $frame = $response->recv(2);
            Assert::isInstanceOf($frame, Swoole\WebSocket\Frame::class);
            Assert::true($response->push((string) $frame->opcode));
            $response->close();
        });
        Swoole\Coroutine::create(function () use ($server) {
            $server->start();
        });
        $opcode = $openPing ? SWOOLE_WEBSOCKET_OPCODE_PING : SWOOLE_WEBSOCKET_OPCODE_TEXT;
        for ($i = 0; $i < 2; $i++) {
            $client = new Swoole\Coroutine\Http\Client('127.0.0.1', $server->port);
            $client->set(['timeout' => 2]);
            Assert::true($client->upgrade('/'));
            Assert::true($client->push('ping', SWOOLE_WEBSOCKET_OPCODE_PING));
            Assert::true($client->push('text'));
            $frame = $client->recv();
            Assert::isInstanceOf($frame, Swoole\WebSocket\Frame::class);
            Assert::same($frame->data, (string) $opcode);
            $client->close();
        }
        $server->shutdown();
    }
    echo "DONE\n";
});
?>
--EXPECT--
DONE
