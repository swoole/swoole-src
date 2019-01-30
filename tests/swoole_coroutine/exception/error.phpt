--TEST--
swoole_coroutine: error
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
echo "\nend\n";
?>
--EXPECTF--
start

Warning: [Coroutine#1] Uncaught Exception: coro Exception %s
Stack trace:
#0 {main}
  thrown in %s/tests/swoole_coroutine/exception/error.php on line 5

end
