--TEST--
swoole_coroutine: max num limit
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
Assert::assert(SWOOLE_CORO_MAX_NUM_LIMIT === PHP_INT_MAX);
echo SWOOLE_CORO_MAX_NUM_LIMIT;
?>
--EXPECTF--
%d
