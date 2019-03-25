--TEST--
swoole_coroutine/exception: error
--SKIPIF--
<?php require  __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';
go(function () {
    echo "start\n";
    throw new Exception('coro Exception');
    co::sleep(.001);
    echo "after sleep\n";
});
echo "end\n";
?>
--EXPECTF--
start

Fatal error: Uncaught Exception: coro Exception %s
Stack trace:
#0 {main}
  thrown in %s/tests/swoole_coroutine/exception/error.php on line 5
