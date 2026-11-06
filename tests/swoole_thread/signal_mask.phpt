--TEST--
swoole_thread: preserve creator signal masks when starting custom and nested threads
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_nts();
skip_if_win();
skip_if_function_not_exist('pcntl_sigprocmask');
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Thread;

$arguments = Thread::getArguments();
if ($arguments === null) {
    Assert::true(pcntl_sigprocmask(SIG_SETMASK, [SIGUSR1], $original));
    try {
        $thread = new Thread(__FILE__, 'child');
        Assert::true(pcntl_sigprocmask(SIG_BLOCK, [SIGUSR1], $actual));
        Assert::same($actual, [SIGUSR1]);
        Assert::true($thread->join());
        Assert::same($thread->getExitStatus(), 0);
    } finally {
        if ($original) {
            pcntl_sigprocmask(SIG_SETMASK, $original);
        } else {
            pcntl_sigprocmask(SIG_UNBLOCK, [SIGUSR1]);
        }
    }
    echo "DONE\n";
} else {
    Assert::true(pcntl_sigprocmask(SIG_BLOCK, [SIGUSR1], $expected));
    foreach ([SIGCHLD, SIGUSR1, SIGTERM] as $signal) {
        Assert::true(in_array($signal, $expected, true));
    }
    if ($arguments[0] === 'child') {
        $thread = new Thread(__FILE__, 'nested');
        Assert::true(pcntl_sigprocmask(SIG_BLOCK, [SIGUSR1], $actual));
        Assert::same($actual, $expected);
        Assert::true($thread->join());
        Assert::same($thread->getExitStatus(), 0);
    }
}
?>
--EXPECT--
DONE
