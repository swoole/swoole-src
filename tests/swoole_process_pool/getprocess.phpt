--TEST--
swoole_process_pool: getProcess
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc';
if (function_exists('msg_get_queue') == false) {
    die("SKIP, no sysvmsg extension.");
}
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$pool = new Swoole\Process\Pool(1);
$pid = posix_getpid();
$pool->on('workerStart', function (Swoole\Process\Pool $pool, int $workerId) use ($pid)
{
    $process = $pool->getProcess();
    Assert::eq($process->pid, posix_getpid());
    posix_kill($pid, SIGTERM);
    sleep(20);
    echo "ERROR\n";
});

$pool->start();
?>
--EXPECT--
