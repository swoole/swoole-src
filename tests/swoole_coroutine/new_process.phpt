--TEST--
swoole_coroutine: new process
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
go(function () {
    $process = new Swoole\Process(function () { });
    $process->start();
});
?>
--EXPECTF--
[%s]	ERROR	(PHP Fatal Error: %d):
Swoole\Process::start: must be forked outside the coroutine
Stack trace:
#0  Swoole\Process->start() called at [%s/tests/swoole_coroutine/new_process.php:%d]
