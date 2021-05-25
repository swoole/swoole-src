--TEST--
swoole_process_pool: getProcess [3]
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc';
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Process\Pool;
use Swoole\Process;

const N = 70000;

$pool = new Pool(2, SWOOLE_IPC_UNIXSOCK);

$pool->on('workerStart', function (Swoole\Process\Pool $pool, int $workerId) {
    if ($workerId == 0) {
        usleep(1000);
        $process1 = $pool->getProcess(1);
        phpt_var_dump($process1);
        $pid1 = $process1->pid;
        Process::kill($process1->pid, SIGTERM);
        usleep(10000);
        $process2 = $pool->getProcess(1);
        phpt_var_dump($process2);
        $pid2 = $process2->pid;
        Assert::notEq($pid1, $pid2);
        $pool->shutdown();
    }
});

$pool->on("message", function ($pool, $data) {

});

$pool->start();
?>
--EXPECT--
