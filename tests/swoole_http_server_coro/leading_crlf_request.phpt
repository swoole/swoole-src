--TEST--
swoole_http_server_coro: request preceded by an empty header block is rejected
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

Coroutine\run(function () {
    $server = new Server('127.0.0.1', 0);
    Coroutine::create(function () use ($server) {
        $server->handle('/', function (Request $request, Response $response) {
            $response->end('body=' . strlen($request->getContent()));
        });
        $server->start();
    });
    Coroutine::sleep(0.001);
    Coroutine::create(function () use ($server) {
        $request = "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n";

        $socket = new Socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
        Assert::true($socket->connect('127.0.0.1', $server->port, -1));
        $socket->sendAll("\r\n\r\n" . $request);
        Assert::contains($socket->recv(), 'HTTP/1.1 400 Bad Request');
        $socket->close();

        // A normal request is still served.
        $socket = new Socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
        Assert::true($socket->connect('127.0.0.1', $server->port, -1));
        $socket->sendAll($request);
        Assert::contains($socket->recv(), 'body=0');
        $socket->close();

        $server->shutdown();
        echo "DONE\n";
    });
});
?>
--EXPECT--
DONE
