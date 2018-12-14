--TEST--
swoole_timer: Timer must be greater than 0
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

assert(@swoole_timer_after(0, function() {}) === false);
assert(@swoole_timer_after(-1, function() {}) === false);
assert(@swoole_timer_tick(0, function() {}) === false);
assert(@swoole_timer_tick(-1, function() {}) === false);
?>
--EXPECTF--
