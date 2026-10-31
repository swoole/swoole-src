--TEST--
swoole_process: restore signal action after removal
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine\System;
use Swoole\Process;
use Swoole\Timer;

function run_with_settings(array $settings, callable $fn): array
{
    $process = new Process(function () use ($settings, $fn) {
        swoole_async_set($settings);
        Co\run($fn);
    });
    $process->start();
    return Process::wait();
}

function wait_for_signal_changes(): void
{
    $ready = new Swoole\Coroutine\Channel(1);
    Swoole\Event::defer(static fn () => $ready->push(true));
    Assert::true($ready->pop(1));
}

$backends = IS_MAC_OS ? [[], ['enable_kqueue' => true]] : [[], ['enable_signalfd' => false]];

foreach ($backends as $settings) {
    $status = run_with_settings($settings, function () {
        Timer::after(10, fn () => Process::kill(getmypid(), SIGTERM));
        Assert::same(System::waitSignal(SIGTERM, 1), SIGTERM);
        // Apply deferred signal changes in thread-context mode before sending again.
        wait_for_signal_changes();
        Process::kill(getmypid(), SIGTERM);
    });
    Assert::same($status['signal'], SIGTERM);

    $status = run_with_settings($settings, function () {
        Process::signal(SIGTERM, function () {});
        Process::signal(SIGTERM, null);
        wait_for_signal_changes();
        Process::kill(getmypid(), SIGTERM);
    });
    Assert::same($status['signal'], SIGTERM);

    $status = run_with_settings($settings, function () {
        Process::signal(SIGTERM, function () {});
        Process::signal(SIGTERM, SIG_IGN);
        wait_for_signal_changes();
        Process::kill(getmypid(), SIGTERM);
        Co::sleep(0.01);
        Assert::true(Process::signal(SIGTERM, function () {}));
        Process::signal(SIGTERM, null);
        Assert::same(Co::stats()['signal_listener_num'], 0);
    });
    Assert::same($status['signal'], 0);

    // PHP ignores SIGPIPE at startup
    $status = run_with_settings($settings, function () {
        Timer::after(10, fn () => Process::kill(getmypid(), SIGPIPE));
        Assert::same(System::waitSignal(SIGPIPE, 1), SIGPIPE);
        wait_for_signal_changes();
        Process::kill(getmypid(), SIGPIPE);
    });
    Assert::same($status['signal'], 0);
}

echo "DONE\n";
?>
--EXPECT--
DONE
