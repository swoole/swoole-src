--TEST--
swoole_process_pool: master pid
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$pool = new Swoole\Process\Pool(1);
$pid = posix_getpid();
$pool->on('workerStart', function (Swoole\Process\Pool $pool, int $workerId) use ($pid)
{
    Assert::assert($pool->master_pid == $pid);
    posix_kill($pid, SIGTERM);
    sleep(20);
    echo "ERROR\n";
});

$pool->start();
?>
--EXPECT--
