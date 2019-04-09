--TEST--
swoole_server: force reload (timer)
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
$pm = new ProcessManager;
$pm->setWaitTimeout(2);
$pm->parentFunc = function () use ($pm) {
    Assert::false(Swoole\Process::kill($pm->getChildPid(), 0));
    $pm->kill(true);
};
$pm->childFunc = function () use ($pm) {
    $server = new Swoole\Server('127.0.0.1', $pm->getFreePort());
    $server->set([
        'reload_async' => true,
        'task_enable_coroutine' => true,
        'max_wait_time' => 1
    ]);
    $server->on('workerStart', function (Swoole\Server $server, int $wid) {
        if ($wid === 0) {
            Swoole\Process::kill($server->master_pid);
            Swoole\Timer::tick(5000, function () {
                echo 'tick';
            });
        }
    });
    $server->on('receive', function () { });
    $server->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECTF--
[%s]	INFO	Server is shutdown now
