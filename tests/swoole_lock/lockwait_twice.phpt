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
$ret = $lock->lockwait(1);
Assert::false($ret);
$end = microtime(true);

Assert::lessThan($end - $start, 2);

?>
--EXPECTF--
bool(true)
