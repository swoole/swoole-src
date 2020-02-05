--TEST--
swoole_http_server_coro: bug no handle
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine;
use Swoole\Http\Status;
use Swoole\Http2;

Coroutine\run(function () {
    $server = new Coroutine\Http\Server('127.0.0.1', 0);
    Coroutine::create(function () use ($server) {
        $server->start();
    });
    Coroutine::create(function () use ($server) {
        $cli = new Coroutine\Http\Client('127.0.0.1', $server->port);
        for ($n = MAX_REQUESTS; $n--;) {
            $cli->get('/');
            Assert::same($cli->statusCode, Status::NOT_FOUND);
        }
        $cli->close();
        if (defined('SWOOLE_USE_HTTP2')) {
            $cli = new Coroutine\Http2\Client('127.0.0.1', $server->port);
            $cli->connect();
            for ($n = MAX_REQUESTS; $n--;) {
                $cli->send(new Http2\Request);
                $response = $cli->recv();
                Assert::same($response->statusCode, Status::NOT_FOUND);
            }
            $cli->close();
        }
        $server->shutdown();
        echo "DONE\n";
    });
});

?>
--EXPECT--
DONE
