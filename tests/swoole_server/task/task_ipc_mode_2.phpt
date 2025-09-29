--TEST--
swoole_server/task: task_ipc_mode = 2
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

use Swoole\Atomic;
use Swoole\Http\Request;
use Swoole\Http\Response;

$pm = new SwooleTest\ProcessManager;
$atomic = new Atomic;
$pm->parentFunc = function ($pid) use ($pm) {
    go(function () use ($pm) {
        echo httpGetBody("http://127.0.0.1:{$pm->getFreePort()}/");
        $pm->kill();
    });
};
$pm->childFunc = function () use ($pm, $atomic) {
    $server = new Swoole\Http\Server('127.0.0.1', $pm->getFreePort(), SERVER_MODE_RANDOM);
    $server->set([
        'log_file' => '/dev/null',
        'open_tcp_nodelay' => true,
        'task_worker_num' => 4,
        'worker_num' => 2,
        'task_ipc_mode' => 2,
        'dispatch_mode' => 2
    ]);
    $server->on('workerStart', function () use ($pm, $atomic) {
        if ($atomic->add() == 6) {
            $pm->wakeup();
        }
    });
    $server->on('request', function (Request $request, Response $response) use ($server) {
        $response->detach();
        $server->task($response->fd);
    });
    $server->on('task', function ($server, $task_id, $worker_id, string $fd) {
        $response = Response::create($fd);
        $response->end("Hello Swoole!\n");
    });
    $server->on('finish', function () { });
    $server->on('close', function () { });
    $server->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
Hello Swoole!
