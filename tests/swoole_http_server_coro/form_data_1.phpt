--TEST--
swoole_http_server_coro: form data 1
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
require __DIR__ . '/../include/api/http_test_cases.php';

use Swoole\Coroutine\Http\Server;
use Swoole\Http\Request;
use Swoole\Http\Response;
use Swoole\Process;
use function Swoole\Coroutine\run;

const OFFSET = 250;

$pm = new ProcessManager;
$pm->initFreePorts();

$pm->parentFunc = function ($pid) use ($pm) {
    form_data_test_1($pm);
};

$pm->childFunc = function () use ($pm) {
    run(function () use ($pm) {
        $server = new Server('127.0.0.1', $pm->getFreePort(), false);
        $server->handle('/', function (Request $request, Response $response) {
            $response->end(json_encode($request->post));
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
DONE
