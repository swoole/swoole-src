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

Assert::setThrowException(true);
$ready = new Swoole\Atomic(0);
$pool = new Pool(2, SWOOLE_IPC_UNIXSOCK);
$pool->set(['max_wait_time' => 2]);

$pool->on('workerStart', function (Pool $pool, int $workerId) use ($ready) {
    if ($workerId == 0) {
        Assert::true($ready->wait(10));
        $process1 = $pool->getProcess(1);
        phpt_var_dump($process1);
        $pid1 = $process1->pid;
        Assert::greaterThan($pid1, 0);
        Assert::true(Process::kill($pid1, SIGTERM));
        Assert::true($ready->wait(10));
        $process2 = $pool->getProcess(1);
        phpt_var_dump($process2);
        $pid2 = $process2->pid;
        Assert::notEq($pid1, $pid2);
        $pool->shutdown();
    } else {
        $ready->wakeup();
    }
});

$pool->on("message", function ($pool, $data) {

});

$pool->start();
?>
--EXPECT--
