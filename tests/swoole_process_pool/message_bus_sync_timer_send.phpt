--TEST--
swoole_process_pool: send a large message from a timer [sync]
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Process\Pool;
use Swoole\Timer;

const SIZE = 8 * 1024 * 1024;

$pool = new Pool(2, SWOOLE_IPC_UNIXSOCK);
$pool->set(['enable_message_bus' => true]);

// A restart loop keeps writing warnings, so the test runner's timeout would never fire.
$pool->on('Start', function (Pool $pool) {
    Timer::after(5000, fn () => $pool->shutdown());
});

$pool->on('WorkerStart', function (Pool $pool, int $workerId) {
    if ($workerId === 0) {
        Timer::after(1, fn () => Assert::true($pool->sendMessage(str_repeat('x', SIZE), 1)));
    }
});

$pool->on('Message', function (Pool $pool, string $data) {
    Assert::same(strlen($data), SIZE);
    echo "DONE\n";
    $pool->shutdown();
});

$pool->start();
?>
--EXPECT--
DONE
