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

$backends = IS_MAC_OS ? [[], ['enable_kqueue' => true]] : [[], ['enable_signalfd' => false]];

foreach ($backends as $settings) {
    $status = run_with_settings($settings, function () {
        Timer::after(10, fn () => Process::kill(getmypid(), SIGTERM));
        Assert::same(System::waitSignal(SIGTERM, 1), SIGTERM);
        Process::kill(getmypid(), SIGTERM);
    });
    Assert::same($status['signal'], SIGTERM);

    $status = run_with_settings($settings, function () {
        Process::signal(SIGTERM, function () {});
        Process::signal(SIGTERM, null);
        Process::kill(getmypid(), SIGTERM);
    });
    Assert::same($status['signal'], SIGTERM);

    $status = run_with_settings($settings, function () {
        Process::signal(SIGTERM, function () {});
        Process::signal(SIGTERM, SIG_IGN);
        Process::kill(getmypid(), SIGTERM);
        Co::sleep(0.01);
        Assert::true(Process::signal(SIGTERM, function () {}));
        Process::signal(SIGTERM, null);
    });
    Assert::same($status['signal'], 0);

    // PHP ignores SIGPIPE at startup
    $status = run_with_settings($settings, function () {
        Timer::after(10, fn () => Process::kill(getmypid(), SIGPIPE));
        Assert::same(System::waitSignal(SIGPIPE, 1), SIGPIPE);
        Process::kill(getmypid(), SIGPIPE);
    });
    Assert::same($status['signal'], 0);
}

echo "DONE\n";
?>
--EXPECT--
DONE
