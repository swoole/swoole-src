--TEST--
swoole_process_pool: getProcess [5]
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc';
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Constant;
use Swoole\Process\Pool;

const N = 70000;

$pool = new Pool(2, SWOOLE_IPC_UNIXSOCK, 0, true);

$pool->on(Constant::EVENT_WORKER_START, function (Pool $pool, int $workerId) {
    if ($workerId == 0) {
        $process1 = $pool->getProcess();
        $process2 = $pool->getProcess(1);
        $process2->write(str_repeat('A', N));
        Assert::same(@$pool->getProcess(2), false);

        if ($process1->read() == 'shutdown') {
            $pool->shutdown();
        }
    }
});

$pool->on(Constant::EVENT_MESSAGE, function ($pool, $data) {
    Assert::length($data, N);
    $process1 = $pool->getProcess(0);
    $process1->write("shutdown");
});

$pool->start();
?>
--EXPECT--
