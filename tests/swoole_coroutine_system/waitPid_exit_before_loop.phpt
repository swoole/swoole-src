--TEST--
swoole_coroutine_system: waitPid for a child that exits before the event loop runs
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_class_not_exist(Swoole\Process::class);
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Atomic;
use Swoole\Coroutine;
use Swoole\Coroutine\System;
use Swoole\Process;

$atomic = new Atomic;

$process = new Process(function () use ($atomic) {
    $atomic->wait(10);
});
$process->start();

Coroutine\run(function () use ($process, $atomic) {
    go(function () use ($process) {
        $status = System::waitPid($process->pid, 1);
        Assert::same($status['pid'], $process->pid);
        echo "DONE\n";
    });
    // the child exits while this coroutine keeps the event loop from running
    $atomic->wakeup();
    $deadline = microtime(true) + 0.1;
    while (microtime(true) < $deadline) {
    }
});

?>
--EXPECT--
DONE
