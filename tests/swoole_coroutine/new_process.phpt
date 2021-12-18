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
--EXPECTREGEX--
Fatal error: Uncaught Swoole\\Error: must be forked outside the coroutine in [\w\W]+php:\d+
Stack trace:
#0 [\w\W]+php\(\d+\): Swoole\\Process->start\(\)
(#1 \[internal function\]: \{closure\}\(\))?|#\d \{main\}
#\d \{main\}|  thrown in [\w\W]+php on line \d+
  thrown in [\w\W]+php on line \d+
