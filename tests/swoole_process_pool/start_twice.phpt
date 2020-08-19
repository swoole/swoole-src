--TEST--
swoole_process_pool: start twice
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Process\Pool;

$pool = new Swoole\Process\Pool(1);

$pool->on("WorkerStart", function (Pool $pool, $workerId) {
    echo "CHILD START\n";
    $pool->shutdown();
    sleep(1);
});

$pool->start();
echo "START 1\n";
$pool->start();
echo "START 2\n";
?>
--EXPECT--
CHILD START
START 1
CHILD START
START 2
