--TEST--
swoole_process_pool: shutdown
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc';
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$pool = new Swoole\Process\Pool(1);
$pool->on('workerStart', function (Swoole\Process\Pool $pool, int $workerId)
{
    $pool->shutdown();
    sleep(20);
    echo "ERROR\n";
});

$pool->start();
?>
--EXPECT--
