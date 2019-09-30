--TEST--
swoole_timer: timer round control
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Timer;
use Swoole\Event;

Timer::after(10, function () {
    Assert::eq(timer::stats()['round'], 1);
    Timer::after(10, function () {
        Assert::eq(timer::stats()['round'], 2);
    });
    usleep(100000);
});

Event::wait();
?>
--EXPECT--
