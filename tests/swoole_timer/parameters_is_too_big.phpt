--TEST--
swoole_timer: The given parameters is too big.
--SKIPIF--
<?php require __DIR__ . "/../include/skipif.inc"; ?>
--INI--
assert.active=1
assert.warning=1
assert.bail=0
assert.quiet_eval=0


--FILE--
<?php
assert(@swoole_timer_after(86400001, function() {}) === false);
assert(@swoole_timer_after(86400001, function() {}) === false);
assert(@swoole_timer_tick(86400001, function() {}) === false);
assert(@swoole_timer_tick(86400001, function() {}) === false);
?>
--EXPECTF--
