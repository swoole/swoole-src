--TEST--
swoole_http_server_coro: chunked and pipeline request
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
require __DIR__ . '/../include/api/http_test_cases.php';

const EOF = "EOF";

use Swoole\Coroutine\Http\Server;
use Swoole\Http\Request;
use Swoole\Http\Response;
use Swoole\Process;
use function Swoole\Coroutine\run;

$pm = new ProcessManager;
$pm->initRandomData(1);
$pm->parentFunc = function () use ($pm) {
    chunked_request($pm);
};
$pm->childFunc = function () use ($pm) {
    run(function () use ($pm) {
        $server = new Server('127.0.0.1', $pm->getFreePort(), false);
        $server->handle('/', function (Request $request, Response $response) {
            $response->end($request->rawContent() . EOF);
        });
        Process::signal(SIGTERM, function () use ($server) {
            $server->shutdown();
        });
        $pm->wakeup();
        $server->start();
    });
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
SUCCESS
