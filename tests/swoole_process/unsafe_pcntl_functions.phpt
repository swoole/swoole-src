--TEST--
swoole_process: the coroutine runtime disables unsafe PCNTL functions while active
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_function_not_exist('pcntl_signal');
skip_if_function_not_exist('pcntl_sigprocmask');
?>
--FILE--
<?php
require __DIR__ . '/../include/Assert.php';

use Swoole\Coroutine;
use SwooleTest\Assert;

function checkPcntlSignalIsEnabled(): void
{
    $handler = pcntl_signal_get_handler(SIGUSR2);
    Assert::true(pcntl_sigprocmask(SIG_BLOCK, [SIGUSR1], $mask));
    try {
        Assert::true(pcntl_signal(SIGUSR2, SIG_IGN));
        Assert::same(pcntl_signal_get_handler(SIGUSR2), SIG_IGN);
    } finally {
        Assert::true(pcntl_signal(SIGUSR2, $handler));
        Assert::true(pcntl_sigprocmask(SIG_SETMASK, $mask));
    }
}

checkPcntlSignalIsEnabled();
for ($i = 0; $i < 2; $i++) {
    Coroutine\run(static function (): void {
        $handler = pcntl_signal_get_handler(SIGUSR2);
        $calls = [
            'pcntl_signal' => static fn () => pcntl_signal(SIGUSR2, SIG_IGN),
            'pcntl_sigprocmask' => static fn () => pcntl_sigprocmask(SIG_UNBLOCK, [SIGUSR1]),
            'pcntl_alarm' => static fn () => pcntl_alarm(0),
            'pcntl_waitid' => static fn () => pcntl_waitid(P_ALL, null, $info, WEXITED | WNOHANG),
            // An invalid flag avoids creating a process if the guard is absent.
            'pcntl_forkx' => static fn () => pcntl_forkx(-1),
        ];
        $expected = [];
        $warnings = [];
        set_error_handler(static function (int $level, string $message) use (&$warnings): bool {
            Assert::same($level, E_WARNING);
            $warnings[] = $message;
            return true;
        });
        try {
            foreach ($calls as $name => $call) {
                if (function_exists($name)) {
                    Assert::null($call());
                    $expected[] = "$name() has been disabled for security reasons";
                }
            }
        } finally {
            restore_error_handler();
        }
        Assert::same($warnings, $expected);
        Assert::same(pcntl_signal_get_handler(SIGUSR2), $handler);
    });
    checkPcntlSignalIsEnabled();
}

echo "DONE\n";
?>
--EXPECT--
DONE
