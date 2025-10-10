--TEST--
swoole_lock: lock timeout
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$lock = new Swoole\Lock();
var_dump($lock->lock());

$start = microtime(true);
$ret = $lock->lock(LOCK_EX, 0.2);
Assert::false($ret);
$end = microtime(true);

Assert::eq($lock->errCode, SOCKET_ETIMEDOUT);
Assert::greaterThanEq($end - $start, 0.2);

?>
--EXPECT--
bool(true)
