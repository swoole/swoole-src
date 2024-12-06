--TEST--
swoole_process_pool: master callback
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc';
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$pool = new Swoole\Process\Pool(1);

$pool->on('workerStart', function (Swoole\Process\Pool $pool, int $workerId) {
    echo "worker start\n";
    Assert::true($pool->workerRunning);
    Assert::eq($pool->workerId, 0);
    Assert::eq($pool->workerPid, posix_getpid());
    pcntl_signal(SIGTERM, function (){

    });
    $pool->shutdown();
    sleep(20);
    echo "worker exit\n";
});

$pool->on('workerStop', function (Swoole\Process\Pool $pool, int $workerId) {
    Assert::false($pool->workerRunning);
    echo "worker stop\n";
});

$pool->on('start', function (Swoole\Process\Pool $pool) {
    Assert::true($pool->running);
    echo "start\n";
});

$pool->on('shutdown', function (Swoole\Process\Pool $pool) {
    Assert::false($pool->running);
    echo "shutdown\n";
});

$pool->start();
?>
--EXPECT--
start
worker start
shutdown
worker exit
worker stop
