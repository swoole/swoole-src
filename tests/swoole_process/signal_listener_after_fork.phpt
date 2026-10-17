--TEST--
swoole_process: child processes do not inherit signal listeners
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine;
use Swoole\Coroutine\System;
use Swoole\Process;

Process::signal(SIGUSR1, function () {});
Process::signal(SIGHUP, SIG_IGN);

// the parent's listener still excludes coroutine signal waits
go(function () {
    Assert::false(System::waitSignal(SIGUSR2, 0.01));
});

$process = new Process(function () {
    Co\run(function () {
        Assert::same(Coroutine::stats()['signal_listener_num'], 0);
        go(function () {
            System::sleep(0.1);
            Process::kill(getmypid(), SIGUSR2);
        });
        Assert::same(System::waitSignal(SIGUSR2, 1), SIGUSR2);
    });
    echo "child\n";
});
$process->start();
Assert::same(Process::wait()['code'], 0);
Process::signal(SIGUSR1, null);
?>
--EXPECTF--
Warning: Swoole\Coroutine\System::waitSignal(): Unable to wait signal, async signal listener has been registered in %s on line %d
child
