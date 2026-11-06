--TEST--
swoole_process: ProcessManager preserves unrelated child exit statuses
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_win();
skip_if_function_not_exist('pcntl_waitpid');
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Process;
use SwooleTest\ProcessManager;

Assert::setThrowException(true);

foreach (['normal', 'signal', 'early-exit', 'timeout'] as $mode) {
    $helper = new Process(function (): void {
        exit(23);
    });
    $helperPid = $helper->start();
    Assert::greaterThan($helperPid, 0);

    $pm = new ProcessManager();
    $pm->setWaitTimeout(1);
    if ($mode === 'signal') {
        $pm->setExpectExitSignal(SIGUSR1);
    }
    $pm->parentFunc = function (): void {
    };
    $pm->childFunc = function () use ($pm, $mode): void {
        if ($mode === 'normal') {
            $pm->wakeup();
            exit(7);
        }
        if ($mode === 'signal') {
            $pm->wakeup();
            Process::kill(getmypid(), SIGUSR1);
        }
        if ($mode === 'early-exit') {
            exit(17);
        }
        while (true) {
            usleep(10000);
        }
    };

    try {
        $failure = null;
        try {
            $pm->run();
        } catch (RuntimeException $e) {
            $failure = $e;
        }
        if ($mode === 'normal' || $mode === 'signal') {
            Assert::null($failure);
            $pm->expectExitCode($mode === 'normal' ? 7 : 0);
        } else {
            $expected = $mode === 'early-exit'
                ? 'ProcessManager child exited with code 17 and signal 0 before sending a wakeup'
                : 'ProcessManager did not receive a wakeup within 1s';
            Assert::isInstanceOf($failure, RuntimeException::class);
            Assert::same($failure->getMessage(), $expected);
        }

        Assert::same(pcntl_waitpid($helperPid, $status), $helperPid);
        Assert::true(pcntl_wifexited($status));
        Assert::same(pcntl_wexitstatus($status), 23);
        Assert::false(@Process::kill($pm->getChildPid(), 0));
    } finally {
        $pm->kill();
        @pcntl_waitpid($helperPid, $status);
        if ($pm->getChildPid() > 0) {
            @pcntl_waitpid($pm->getChildPid(), $status);
        }
    }
}

echo "DONE\n";
?>
--EXPECT--
DONE
