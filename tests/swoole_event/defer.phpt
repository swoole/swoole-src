--TEST--
swoole_event: Swoole\Event::defer
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

Swoole\Event::defer(function () {
    echo "defer [1]\n";
});
Swoole\Timer::after(100, function () {
    echo "timer [1]\n";
    Swoole\Timer::after(100, function () {
        echo "timer [2]\n";
    });
    Swoole\Event::defer(function () {
        echo "defer [2]\n";
    });
});
Swoole\Event::wait();
?>
--EXPECT--
defer [1]
timer [1]
defer [2]
timer [2]
