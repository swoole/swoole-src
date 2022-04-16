--TEST--
swoole_event: Swoole\Event::defer and sleep
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
go(function () {
    co::sleep(0.001);
    echo "timer [1]\n";
    Swoole\Event::defer(function () {
        echo "defer [2]\n";
        go(function () {
            co::sleep(0.001);
            echo "timer [2]\n";
        });
    });
});
Swoole\Event::defer(function () {
    echo "defer [1]\n";
});
Swoole\Event::wait();
?>
--EXPECT--
defer [1]
timer [1]
defer [2]
timer [2]
