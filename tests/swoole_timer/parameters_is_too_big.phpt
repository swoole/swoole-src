--TEST--
swoole_timer: The given parameters is too big.
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

assert(@swoole_timer_after(86400001, function() {}) === false);
assert(@swoole_timer_after(86400001, function() {}) === false);
assert(@swoole_timer_tick(86400001, function() {}) === false);
assert(@swoole_timer_tick(86400001, function() {}) === false);
?>
--EXPECTF--
