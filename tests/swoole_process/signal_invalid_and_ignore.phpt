--TEST--
swoole_process: signal rejects uncatchable signals and SIG_IGN can be removed
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Process;

Co\run(function () {
    foreach ([0, SIGKILL, SIGSTOP] as $signo) {
        Assert::false(@Process::signal($signo, function () {}));
    }

    Assert::true(Process::signal(SIGUSR1, SIG_IGN));
    Assert::true(Process::signal(SIGUSR1));
    Assert::false(@Process::signal(SIGUSR1));

    $got = false;
    Assert::true(Process::signal(SIGUSR1, function () use (&$got) {
        $got = true;
    }));
    posix_kill(getmypid(), SIGUSR1);
    Co::sleep(0.05);
    Assert::true($got);
    Process::signal(SIGUSR1, null);
});
echo "DONE\n";
?>
--EXPECT--
DONE
