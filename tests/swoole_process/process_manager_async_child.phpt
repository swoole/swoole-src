--TEST--
swoole_process: ProcessManager drains asynchronous work after the child callback returns
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine;
use Swoole\Event;
use Swoole\Timer;
use SwooleTest\ProcessManager;

$pm = new ProcessManager();
$pm->setWaitTimeout(2);
$pm->childFunc = function () use ($pm): void {
    Event::defer(function (): void {
        echo "defer\n";
    });
    Timer::after(10, function () use ($pm): void {
        Coroutine::create(function () use ($pm): void {
            Coroutine::sleep(0.001);
            echo "coroutine\n";
            $pm->wakeup();
            Event::defer(function (): void {
                echo "drained\n";
            });
        });
        echo "timer\n";
    });
};
$pm->parentFunc = function (): void {
};
$pm->childFirst();
$pm->run();
$pm->expectExitCode(0);
echo "DONE\n";
?>
--EXPECT--
defer
timer
coroutine
drained
DONE
