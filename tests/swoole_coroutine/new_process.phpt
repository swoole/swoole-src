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
Fatal error: Uncaught Swoole\Error: must be forked outside the coroutine in %s:%d
Stack trace:
#0 %s(5): Swoole\Process->start()
#1 {main}
  thrown in %s on line %d
