--TEST--
swoole_lock: lock nb
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$lock = new Swoole\Lock();
Assert::true($lock->lock());

$ret = $lock->lock(LOCK_EX | LOCK_NB);
Assert::false($ret);

$lock->unlock();
Assert::true($lock->lock(LOCK_EX | LOCK_NB));
?>
--EXPECT--
