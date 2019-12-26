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

const REQUEST = "GET / HTTP/1.1\r\nContent-Length: invalid\r\n\r\n";

Coroutine\run(function () {
    $server = new Server('127.0.0.1', 0);
    Coroutine::create(function () use ($server) {
        $server->handle('/', function (Request $request, Response $response) use ($server) {
            echo "never here\n";
        });
        $server->start();
    });
    Coroutine::sleep(0.001);
    Coroutine::create(function () use ($server) {
        $socket = new Socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
        if (Assert::true($socket->connect('127.0.0.1', $server->port, -1))) {
            $ret = $socket->sendAll(REQUEST);
            Assert::same($ret, strlen(REQUEST));
            Assert::contains($socket->recv(), 'HTTP/1.1 400 Bad Request');
            $server->shutdown();
            echo "DONE\n";
        }
    });
});

?>
--EXPECT--
DONE
