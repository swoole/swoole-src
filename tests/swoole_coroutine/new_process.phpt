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
[%s]	ERROR	must be forked outside the coroutine.
