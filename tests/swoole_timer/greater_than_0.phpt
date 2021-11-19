--TEST--
swoole_timer: Timer must be greater than 0
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

Assert::false(@Swoole\Timer::after(0, function() {}));
Assert::false(@Swoole\Timer::after(-1, function() {}));
Assert::false(@Swoole\Timer::tick(0, function() {}));
Assert::false(@Swoole\Timer::tick(-1, function() {}));
?>
--EXPECTF--
