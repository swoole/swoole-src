--TEST--
swoole_http_server_coro: bad request
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine;
use Swoole\Coroutine\Http\Server;
use Swoole\Coroutine\Socket;
use Swoole\Http\Request;
use Swoole\Http\Response;

const REQUEST =
    "GET /websocket HTTP/1.1\r\n" .
    "Host: 127.0.0.1\r\n" .
    "Connection: Upgrade\r\n" .
    "Upgrade: websocket\r\n" .
    "Sec-WebSocket-Version: 13\r\n" .
    "Sec-WebSocket-Key: ZE5FYi8lZlZBbnlrTmxYKQ==\r\n\r\n" .
    "\x81\x0cHello Swoole";

Coroutine\run(function () {
    $server = new Server('127.0.0.1', 0);
    Coroutine::create(function () use ($server) {
        $server->handle('/', function (Request $request, Response $websocket) use ($server) {
            $websocket->upgrade();
            $frame = $websocket->recv();
            if ($frame) {
                $websocket->push($frame);
            }
        });
        $server->start();
    });
    Coroutine::sleep(0.001);
    Coroutine::create(function () use ($server) {
        $socket = new Socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
        if (Assert::true($socket->connect('127.0.0.1', $server->port, -1))) {
            $ret = $socket->sendAll(REQUEST);
            Assert::same($ret, strlen(REQUEST));
            // The handshake and echoed WebSocket frame may arrive in separate reads.
            $reply = '';
            while (!str_contains($reply, 'Hello Swoole')) {
                $chunk = $socket->recv(65536, 5);
                Assert::notEmpty($chunk);
                $reply .= $chunk;
            }
            $server->shutdown();
            echo "DONE\n";
        }
    });
});

?>
--EXPECT--
DONE
