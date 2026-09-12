--TEST--
swoole_process_pool: restore signal disposition
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_not_linux();
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Process;
use Swoole\Process\Pool;

function assertSignalRestored(Closure $start): void
{
    $process = new Process(function () use ($start) {
        $start();

        Process::kill(getmypid(), SIGIO);
        usleep(100000);
        exit(99);
    });

    $process->start();
    $status = Process::wait();

    Assert::same($status['signal'], SIGIO);
}

assertSignalRestored(function () {
    $pool = new Pool(1);
    $pool->on('workerStart', function (Pool $pool) {
        $pool->shutdown();
    });
    $pool->start();
});

assertSignalRestored(function () {
    $pool = new Pool(1);
    $pool->on('workerExit', function () {});

    try {
        $pool->start();
    } catch (Swoole\Exception $exception) {
        Assert::same($exception->getMessage(), 'cannot set `onWorkerExit` without enable_coroutine');
    }
});

echo "DONE\n";
?>
--EXPECT--
DONE
