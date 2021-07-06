--TEST--
swoole_lock: test lock twice
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$lock = new Swoole\Lock();
var_dump($lock->lock());


$start = microtime(true);
$ret = $lock->lockwait(0.2);
Assert::false($ret);
$end = microtime(true);

Assert::eq($lock->errCode, SOCKET_ETIMEDOUT);
Assert::lessThan($end - $start, 0.2);

?>
--EXPECT--
bool(true)
