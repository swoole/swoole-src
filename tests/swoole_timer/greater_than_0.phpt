--TEST--
swoole_timer: Timer must be greater than 0
--SKIPIF--
<?php require __DIR__ . "/../include/skipif.inc"; ?>
--INI--
assert.active=1
assert.warning=1
assert.bail=0
assert.quiet_eval=0


--FILE--
<?php
assert(@swoole_timer_after(0, function() {}) === false);
assert(@swoole_timer_after(-1, function() {}) === false);
assert(@swoole_timer_tick(0, function() {}) === false);
assert(@swoole_timer_tick(-1, function() {}) === false);
?>
--EXPECTF--
