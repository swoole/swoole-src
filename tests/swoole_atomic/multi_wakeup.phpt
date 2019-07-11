--TEST--
swoole_atomic: multi wakeup
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
$pm = new ProcessManager();
$pm->setWaitTimeout(5);
$s = microtime(true);
$pm->parentFunc = function () use ($pm, $s) {
    echo "WAKED\n";
    $s = microtime(true) - $s;
    Assert::assert($s < 1);
    usleep(1000);
    $pm->kill();
};
$pm->childFunc = function () use ($pm) {
    $server = new Swoole\Http\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_PROCESS);
    $server->set(['worker_num' => 4, 'log_file' => '/dev/null']);
    $server->on('workerStart', function () use ($pm) {
        Assert::assert($pm->wakeup());
    });
    $server->on('request', function () { });
    $server->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
WAKED
