--TEST--
swoole_process_pool: stop a synchronous worker that uses a timer
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Atomic;
use Swoole\Process\Pool;
use Swoole\Timer;

$stops = new Atomic();

foreach ([[SWOOLE_IPC_UNIXSOCK, false], [SWOOLE_IPC_UNIXSOCK, true], [SWOOLE_IPC_SOCKET, false]] as [$ipcType, $enableMessageBus]) {
    $stops->set(0);

    $pool = new Pool(1, $ipcType);
    $pool->set(['enable_message_bus' => $enableMessageBus]);
    if ($ipcType === SWOOLE_IPC_SOCKET) {
        $pool->listen('127.0.0.1', get_one_free_port());
    }

    // A restart loop keeps writing warnings, so the test runner's timeout would never fire.
    $pool->on('Start', function (Pool $pool) {
        Timer::after(5000, fn () => $pool->shutdown());
    });
    $pool->on('WorkerStart', function (Pool $pool) {
        Timer::after(10, fn () => $pool->shutdown());
        // Wakes the worker even if SIGTERM lands just before it starts waiting.
        Timer::tick(10, function () {});
    });
    $pool->on('Message', function () {});
    $pool->on('WorkerStop', function () use ($stops) {
        $stops->add();
    });

    $pool->start();

    Assert::same($stops->get(), 1);
}
echo "DONE\n";
?>
--EXPECT--
DONE
