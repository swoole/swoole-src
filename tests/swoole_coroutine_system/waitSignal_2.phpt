--TEST--
swoole_coroutine_system: waitSignal 2
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Atomic;
use Swoole\Coroutine;
use Swoole\Coroutine\System;
use Swoole\Process;

$atomic = new Atomic;

$pid = getmypid();
$killer = new Process(function () use ($pid, $atomic) {
    $atomic->wait();
    echo "2\n";
    switch_process();
    Process::kill($pid, SIGUSR1);
    $atomic->wait();
    echo "6\n";
    switch_process();
    Process::kill($pid, SIGUSR2);
    echo "8\n";
});
$killer->start();

Coroutine\run(function () use ($atomic) {
    Coroutine::sleep(0.001);
    switch_process();
    $atomic->wakeup();
    echo "1\n";
    $list = [SIGUSR1, SIGUSR2, SIGIO];
    Assert::eq(System::waitSignal($list), SIGUSR1);
    echo "3\n";
    Assert::false(System::waitSignal($list, 0.01));
    echo "4\n";
    $atomic->wakeup();
    echo "5\n";
    Assert::eq(System::waitSignal($list), SIGUSR2);
    echo "7\n";
    System::wait();
    echo "9\n";
});

?>
--EXPECT--
1
2
3
4
5
6
8
7
9
