--TEST--
swoole_process: shutdown in task process
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Http\Server;
use Swoole\Http\Request;
use Swoole\Http\Response;

$pm = new SwooleTest\ProcessManager;
$pm->parentFunc = function () use ($pm) {
    Co\run(function () use ($pm) {
        httpGetBody("http://127.0.0.1:{$pm->getFreePort()}/");
    });
    usleep(100000);
    $pm->kill();
};

$pm->childFunc = function () use ($pm) {
    $serv = new Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $serv->set([
        'worker_num' => 2,
        'task_worker_num' => 1,
        'log_file' => '/dev/null',
    ]);

    $serv->on('ManagerStart', function (Server $serv) use ($pm) {
        $pm->wakeup();
    });

    $serv->on('workerStop', function ($server) {
        echo "worker exit\n";
    });

    $serv->on('Task', function ($server, $taskId, $workerId, $data) use ($pm) {
        $server->shutdown();
        $pm->wakeup();
    });

    $serv->on('Request', function (Request $request, Response $response) use ($serv) {
        $response->end('Hello Swoole');
        $serv->task('a');
    });
    $serv->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
worker exit
worker exit
worker exit
