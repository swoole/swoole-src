--TEST--
swoole_http_server/task: use async io and coroutine in task process
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';
$pm = new ProcessManager;
$pm->parentFunc = function ($pid) use ($pm) {
    usleep(100 * 1000);
    $pm->kill();
};
$pm->childFunc = function () use ($pm) {
    $server = new swoole_http_server('127.0.0.1', $pm->getFreePort(), SWOOLE_PROCESS);
    $server->set([
        'log_file' => '/dev/null',
        'task_worker_num' => 1,
        'task_enable_coroutine' => true
    ]);
    $server->on('workerStart', function (swoole_http_server $server, int $wid) use ($pm) {
        if ($wid === 0) {
            $server->taskCo(['foo'], 1);
        }
    });
    $server->on('workerError', function (swoole_http_server $server) use ($pm) {
        $pm->wakeup();
    });
    $server->on('request', function () { });
    $server->on('task', function (swoole_http_server $server, swoole_server_task $task) use ($pm) {
        $server->finish('bar');
    });
    $server->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECTF--
Fatal error: Swoole\Server::finish(): please use Swoole\Server\Task->finish instead when task_enable_coroutine is enable in %s/task/enable_coroutine_with_wrong_usage.php on line %d
