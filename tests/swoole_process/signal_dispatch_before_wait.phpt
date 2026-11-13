--TEST--
swoole_process: dispatch a signal caught before the event loop waits
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine\System;
use Swoole\Process;

// Backends where the event loop dispatches signals caught by a sigaction handler
$backends = IS_MAC_OS ? [[], ['enable_kqueue' => true]] : [['enable_signalfd' => false]];

foreach ($backends as $settings) {
    $process = new Process(function () use ($settings) {
        swoole_async_set($settings);

        // Each run catches its signal before the event loop first waits
        Co\run(function () {
            $start = microtime(true);
            Process::signal(SIGUSR1, function () use ($start) {
                Assert::lessThan(microtime(true) - $start, 0.5);
                Process::signal(SIGUSR1, null);
            });
            Process::kill(getmypid(), SIGUSR1);
            Co::sleep(1);
        });

        $child = new Process(function () {
            sleep(10);
        });
        $pid = $child->start();
        Co\run(function () use ($pid) {
            $start = microtime(true);
            go(function () use ($pid, $start) {
                Assert::same(System::waitPid($pid, 3)['pid'], $pid);
                Assert::lessThan(microtime(true) - $start, 1);
            });
            Process::kill($pid, SIGTERM);
            while (microtime(true) - $start < 0.3);
        });
    });
    $process->start();
    $status = Process::wait();
    Assert::same($status['signal'], 0);
    Assert::same($status['code'], 0);
}

echo "DONE\n";
?>
--EXPECT--
DONE
