--TEST--
swoole_coroutine_system: waitSignal
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine;
use Swoole\Coroutine\System;
use Swoole\Process;

$pid = getmypid();
$sender = new Process(function () use ($pid) {
    Process::kill($pid, SIGUSR1);
    usleep(100 * 1000);
    Process::kill($pid, SIGUSR2);
});
$sender->start();

Coroutine\run(function () {
    Assert::true(System::waitSignal(SIGUSR1));
    Assert::false(System::waitSignal(SIGUSR2, 0.01));
    Assert::true(System::waitSignal(SIGUSR2));
    System::wait();
});

?>
--EXPECTF--
