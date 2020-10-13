--TEST--
swoole_http_server_coro: bug 3025 getData
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine;
use Swoole\Coroutine\Http\Server;
use Swoole\Http\Request;
use Swoole\Http\Response;

Coroutine\run(function () {
    $server = new Server('127.0.0.1', 0);
    Coroutine::create(function () use ($server) {
        $server->handle('/', function (Request $request, Response $response) {
            static $length;
            if (!isset($length)) {
                $length = strlen($request->getData());
            } else {
                Assert::same(strlen($request->getData()), $length);
            }
        });
        $server->start();
    });
    Coroutine::create(function () use ($server) {
        $cli = new Swoole\Coroutine\Http\Client('127.0.0.1', $server->port);
        for ($n = MAX_REQUESTS; $n--;) {
            $cli->get('/');
        }
        $server->shutdown();
        echo "DONE\n";
    });
});

?>
--EXPECT--
DONE
