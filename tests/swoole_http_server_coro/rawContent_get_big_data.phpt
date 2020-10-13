--TEST--
swoole_http_server_coro: rawContent get big data
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine\Http\Server;
use Swoole\Http\Request;
use Swoole\Http\Response;
use function Swoole\Coroutine\run;

$pm = new SwooleTest\ProcessManager;
$pm->initRandomData(1, 64 * 1024);
$pm->parentFunc = function () use ($pm) {
    run(function () use($pm) {
        httpRequest("http://127.0.0.1:{$pm->getFreePort()}/", [
            'method' => 'POST',
            'data' => $pm->getRandomData(),
        ]);
    });
    $pm->kill();
};
$pm->childFunc = function () use ($pm) {
    run(function () use($pm) {
        $server = new Server('127.0.0.1', $pm->getFreePort());
        $server->handle('/', function (Request $request, Response $response) use ($pm) {
            Assert::assert($request->rawContent() === $pm->getRandomData());
            Assert::length($request->rawContent(), 64 * 1024);
        });
        $server->start();
    });
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
