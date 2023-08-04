--TEST--
swoole_event: cycle
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$n = 0;
Assert::false(Swoole\Event::cycle(null));
Swoole\Event::cycle(function () use (&$n) {
    echo "cycle [$n]\n";
    $n++;
    if ($n == 3) {
        Swoole\Event::cycle(null);
    }
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
cycle [0]
timer [1]
defer [2]
cycle [1]
timer [2]
cycle [2]
