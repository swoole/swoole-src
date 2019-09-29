--TEST--
swoole_server: bug Github#2313
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
$pm = new SwooleTest\ProcessManager;
$pm->childFunc = function () use ($pm) {
    $server = new Swoole\Server('127.0.0.1', 9501);
    $process = new Swoole\Process(function () { });
    $server->addProcess($process);
    var_dump($process->id);
    $pm->wakeup();
};
$pm->childFirst();
$pm->run();
?>
--EXPECTF--
int(%d)
