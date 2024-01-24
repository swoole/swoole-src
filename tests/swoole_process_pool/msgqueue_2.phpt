--TEST--
swoole_process_pool: sysv msgqueue [2]
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc';
if (function_exists('msg_get_queue') == false) {
    die("SKIP, no sysvmsg extension.");
}
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Process\Pool;

const MSGQ_KEY = 0x70000001;

$pool = new Pool(2, SWOOLE_IPC_MSGQUEUE, MSGQ_KEY);

$pool->on('workerStart', function (Pool $pool, int $workerId) {
    if ($workerId == 0) {
        echo "worker start\n";
        Assert::true($pool->getProcess()->push('hello world' . PHP_EOL));
    } else {
        echo $pool->getProcess()->pop();
        $pool->shutdown();
    }
});

$pool->on('workerStop', function (Pool $pool, int $workerId) {
    if ($workerId == 1) {
        echo "worker stop\n";
    }
});

$pool->start();
?>
--EXPECT--
worker start
hello world
worker stop
