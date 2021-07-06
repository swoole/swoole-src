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
$lock->lockwait(1);
$end = microtime(true);

assert($end - $start < 2);

?>
--EXPECTF--
bool(true)
