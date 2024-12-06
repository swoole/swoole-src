--TEST--
swoole_process_pool: worker exit
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Timer;

$pool = new Swoole\Process\Pool(1, SWOOLE_IPC_NONE, 0, true);

$GLOBALS['running'] = true;
$GLOBALS['count'] = 1;

$pool->on('workerStart', function (Swoole\Process\Pool $pool, int $workerId) {
    echo "worker start\n";
    Assert::eq($pool->workerId, $workerId);

    $count = 0;
    while ($GLOBALS['running']) {
        Co::sleep(0.03);
        echo "sleep\n";
        if (++$count === 3) {
            $pool->shutdown();
        }
    }
});

$pool->on('workerStop', function ($pool, $data) {
    echo "worker stop\n";
});

$pool->on('workerExit', function ($pool, $data) {
    $GLOBALS['count']++;
    if ($GLOBALS['count'] == 3) {
        $GLOBALS['running'] = false;
    }
    echo ('worker exit') . PHP_EOL;
});

$pool->start();
?>
--EXPECT--
worker start
sleep
sleep
sleep
worker exit
sleep
worker exit
sleep
worker exit
worker stop
