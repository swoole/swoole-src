--TEST--
swoole_process_pool: a timer owned by a reactor created in the master is kept after start() returns
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Event;
use Swoole\Process\Pool;
use Swoole\Timer;

$deferred = false;
$timerId  = null;
$pool     = new Pool(1, SWOOLE_IPC_NONE);
$pool->on('WorkerStart', function (Pool $pool) {
    $pool->shutdown();
});
$pool->on('Shutdown', function () use (&$deferred, &$timerId) {
    Event::defer(function () use (&$deferred) {
        $deferred = true;
    });
    $timerId = Timer::after(60000, function () {});
});
$pool->start();
Assert::true(Timer::exists($timerId));
Timer::clear($timerId);
Event::wait();
Assert::true($deferred);
echo "DONE\n";
?>
--EXPECT--
DONE
