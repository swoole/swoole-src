--TEST--
swoole_atomic: add/sub/get/cmpset
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$atomic = new swoole_atomic(1);

assert($atomic->add(199) == 200);
assert($atomic->sub(35) == 165);
assert($atomic->get() == 165);
assert($atomic->cmpset(165, 1));
assert(!$atomic->cmpset(1555, 0));
?>
--EXPECT--
