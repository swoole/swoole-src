--TEST--
swoole_process_pool: shutdown cancels its force-kill timer after workers exit
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Atomic;
use Swoole\Process\Pool;
use Swoole\Timer;

$ready = new Atomic();
$timedOut = new Atomic();
$pool = new Pool(1, SWOOLE_IPC_NONE);
$pool->set(['max_wait_time' => 1]);
$pool->on('WorkerStart', function () use ($ready) {
    $ready->set(1);
    // SIGTERM can terminate this worker immediately, without waiting for the force-kill timer.
    while (true) {
        usleep(1000);
    }
});
$watchdog = null;
$pool->on('Start', function (Pool $pool) use ($ready, $timedOut, &$watchdog) {
    $watchdog = Timer::after(5000, function () use ($pool, $timedOut) {
        $timedOut->set(1);
        $pool->shutdown();
    });
    Timer::tick(10, function ($id) use ($pool, $ready) {
        if ($ready->get()) {
            Timer::clear($id);
            $pool->shutdown();
        }
    });
});
$pool->start();
Timer::clear($watchdog);
Assert::same($timedOut->get(), 0);
Assert::same(Timer::stats()['num'], 0);
unset($pool);
echo "DONE\n";
?>
--EXPECT--
DONE
