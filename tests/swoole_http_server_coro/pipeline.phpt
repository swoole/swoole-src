--TEST--
swoole_http_server_coro: pipeline
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

const REQUEST = "GET / HTTP/1.1\r\n\r\n";

Coroutine\run(function () {
    $server = new Server('127.0.0.1', 0);
    Coroutine::create(function () use ($server) {
        $server->handle('/', function (Request $request, Response $response) use ($server) {
            static $count = 0;
            $response->end("OK\n");
            if (++$count === MAX_CONCURRENCY * MAX_REQUESTS) {
                echo "DONE\n";
                $server->shutdown();
            }
        });
        $server->start();
    });
    for ($c = MAX_CONCURRENCY; $c--;) {
        Coroutine::sleep(0.001);
        Coroutine::create(function () use ($server) {
            $socket = new Socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
            if (Assert::true($socket->connect('127.0.0.1', $server->port, -1))) {
                $ret = $socket->sendAll(str_repeat(REQUEST, MAX_REQUESTS));
                Assert::same($ret, strlen(REQUEST) * MAX_REQUESTS);
            } else {
                throw new RuntimeException('Connect failed: ' . $socket->errMsg);
            }
            while (!empty($socket->recv())) {
                // pass
            }
        });
    }
});

?>
--EXPECT--
DONE
