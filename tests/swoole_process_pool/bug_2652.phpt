--TEST--
swoole_process_pool: bug Github#2639
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

const MSGQ_KEY = 0x666;
$pool = new Swoole\Process\Pool(1);

$pool->on('workerStart', function (Swoole\Process\Pool $pool, int $workerId) {
    $pool->getProcess($workerId)->useQueue(MSGQ_KEY);
    $pool->getProcess($workerId)->push('test');
    Assert::same('test', $pool->getProcess($workerId)->pop());
    $pool->shutdown();
    sleep(20);
    echo "ERROR\n";
});
$pool->start();
?>
--EXPECT--
