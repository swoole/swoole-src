--TEST--
swoole_coroutine_system: preserve ignored signals after temporary waits
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_class_not_exist(Swoole\Process::class);
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine;
use Swoole\Coroutine\System;
use Swoole\Process;
use Swoole\Timer;

function wait_for_signal_changes(): void
{
    $ready = new Swoole\Coroutine\Channel(1);
    Swoole\Event::defer(static fn () => $ready->push(true));
    Assert::true($ready->pop(1));
}

$backends = IS_MAC_OS ? [[], ['enable_kqueue' => true]] : [[], ['enable_signalfd' => false]];

foreach ($backends as $settings) {
    $process = new Process(static function () use ($settings): void {
        swoole_async_set($settings);
        Assert::true(Process::signal(SIGTERM, SIG_IGN));

        Coroutine\run(static function (): void {
            Assert::same(Coroutine::stats()['signal_listener_num'], 0);
            Assert::false(System::waitSignal(SIGTERM, 0.01));
            // Apply deferred restorations in thread-context mode before sending again.
            wait_for_signal_changes();
            Process::kill(getmypid(), SIGTERM);
            Coroutine::sleep(0.01);

            // Reject an invalid list without leaving SIGUSR1 registered.
            Assert::false(@System::waitSignal([SIGUSR1, SIGCHLD], 0.01));
            wait_for_signal_changes();
            Assert::true(Process::signal(SIGUSR1, static function (): void {}));
            Assert::true(Process::signal(SIGUSR1, null));
            Assert::same(Coroutine::stats()['signal_listener_num'], 0);

            Timer::after(10, static fn () => Process::kill(getmypid(), SIGTERM));
            Assert::same(System::waitSignal([SIGTERM, SIGTERM], 1), SIGTERM);
            wait_for_signal_changes();
            Process::kill(getmypid(), SIGTERM);
            Coroutine::sleep(0.01);

            // Ignoring SIGTERM must not prevent waiting for another signal.
            Timer::after(10, static fn () => Process::kill(getmypid(), SIGUSR1));
            Assert::same(System::waitSignal([SIGUSR1, SIGTERM], 1), SIGUSR1);
            wait_for_signal_changes();
            Process::kill(getmypid(), SIGTERM);
            Coroutine::sleep(0.01);
        });
    });
    Assert::greaterThan($process->start(), 0);
    $status = Process::wait();
    Assert::same($status['signal'], 0);
    Assert::same($status['code'], 0);
}

echo "DONE\n";
?>
--EXPECT--
DONE
