--TEST--
swoole_timer: Timer must be greater than 0
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

Assert::false(@swoole_timer_after(0, function() {}));
Assert::false(@swoole_timer_after(-1, function() {}));
Assert::false(@swoole_timer_tick(0, function() {}));
Assert::false(@swoole_timer_tick(-1, function() {}));
?>
--EXPECTF--
