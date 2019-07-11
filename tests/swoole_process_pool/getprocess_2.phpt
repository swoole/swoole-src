--TEST--
swoole_process_pool: getProcess [2]
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc';
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

const N = 70000;

$pool = new Swoole\Process\Pool(2, SWOOLE_IPC_UNIXSOCK);

$pool->on('workerStart', function (Swoole\Process\Pool $pool, int $workerId) {
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

$pool->on("message", function ($pool, $data) {
    Assert::length($data, N);
    $process1 = $pool->getProcess(0);
    $process1->write("shutdown");
});

$pool->start();
?>
--EXPECT--
