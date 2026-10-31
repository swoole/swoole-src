--TEST--
swoole_process_pool: message bus timer [sync]
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Atomic;
use Swoole\Process\Pool;
use Swoole\Timer;

const TICKS = 2;

$starts = new Atomic();
$ticks = new Atomic();
$idleTicks = new Atomic();
$trafficTicks = new Atomic();

$pool = new Pool(2, SWOOLE_IPC_UNIXSOCK);
$pool->set(['enable_message_bus' => true]);

$pool->on('WorkerStart', function (Pool $pool, int $workerId) use ($starts, $ticks, $idleTicks, $trafficTicks) {
    if ($workerId === 0) {
        $starts->add();
        Timer::tick(50, fn () => $ticks->add());
        return;
    }

    $deadline = microtime(true) + 2;
    while ($ticks->get() < TICKS && microtime(true) < $deadline) {
        usleep(1000);
    }
    $idleTicks->set($ticks->get());

    // Messages arrive faster than the tick, so its deadline never expires during the pipe wait.
    $deadline = microtime(true) + 2;
    while ($ticks->get() < $idleTicks->get() + TICKS && microtime(true) < $deadline) {
        $pool->sendMessage('x', 0);
        usleep(1000);
    }
    $trafficTicks->set($ticks->get() - $idleTicks->get());
    $pool->shutdown();
});

$pool->on('Message', function () {});

$pool->start();

Assert::same($starts->get(), 1);
Assert::greaterThanEq($idleTicks->get(), TICKS);
Assert::greaterThanEq($trafficTicks->get(), TICKS);
echo "DONE\n";
?>
--EXPECT--
DONE
