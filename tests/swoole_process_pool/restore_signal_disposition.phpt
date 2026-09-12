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

$process = new Process(function () {
    $pool = new Pool(1);
    $pool->on('workerStart', function (Pool $pool) {
        $pool->shutdown();
    });
    $pool->start();

    Process::kill(getmypid(), SIGIO);
    usleep(100000);
    exit(99);
});

$process->start();
$status = Process::wait();

Assert::same($status['signal'], SIGIO);
echo "DONE\n";
?>
--EXPECT--
DONE
