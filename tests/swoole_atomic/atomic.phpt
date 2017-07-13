--TEST--
swoole_atomic: add/sub/get/cmpset
--SKIPIF--
<?php require __DIR__ . "/../include/skipif.inc"; ?>
--INI--
assert.active=1
assert.warning=1
assert.bail=0
assert.quiet_eval=0

--FILE--
<?php
$atomic = new swoole_atomic(1);

assert($atomic->add(199) == 200);
assert($atomic->sub(35) == 165);
assert($atomic->get() == 165);
assert($atomic->cmpset(165, 1));
assert(!$atomic->cmpset(1555, 0));
?>

--EXPECT--

