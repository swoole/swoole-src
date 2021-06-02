--TEST--
swoole_coroutine_system: waitSignalProcess
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Atomic;
use Swoole\Coroutine;
use Swoole\Coroutine\System;
use Swoole\Event;
use Swoole\Process;

$atomic = new Atomic();

Coroutine::create(function () {
    $result = System::waitSignal(\SIGUSR1);
    var_dump('parent', $result);
});

$parentPid = getmypid();

$process = new Process(function ($process) use ($atomic, $parentPid) {
    var_dump('process');
    Co\run(function () use ($parentPid, $process) {
        $result = System::waitSignal(\SIGUSR2);
        var_dump('child', $result);
        Process::kill($parentPid, \SIGUSR1);
        $process->exit();
    });
    $atomic->wakeup();
});
$process->start();
$atomic->wait();
var_dump(Process::kill($process->pid, \SIGUSR2));
Event::wait();
?>
--EXPECT--
string(7) "process"
bool(true)
string(5) "child"
bool(true)
string(6) "parent"
bool(true)
