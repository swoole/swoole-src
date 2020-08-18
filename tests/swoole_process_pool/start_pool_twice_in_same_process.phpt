--TEST--
swoole_process_pool: start pool twice in the same process
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Process\Pool;

$pool = new Swoole\Process\Pool(1);

$pool->on("WorkerStart", function (Pool $pool, $workerId) {
    $pool->shutdown();
});

$pool->start();

$pool = new Swoole\Process\Pool(1);

$pool->on("WorkerStart", function (Pool $pool, $workerId) {
    $pool->shutdown();
});

$pool->start();
echo "DONE\n";
?>
--EXPECT--
DONE
