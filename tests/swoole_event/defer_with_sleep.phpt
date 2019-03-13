--TEST--
swoole_event: swoole_event_defer and sleep
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
go(function () {
    co::sleep(0.001);
    echo "timer [1]\n";
    swoole_event_defer(function () {
        echo "defer [2]\n";
        go(function () {
            co::sleep(0.001);
            echo "timer [2]\n";
        });
    });
});
swoole_event_defer(function () {
    echo "defer [1]\n";
});
swoole_event_wait();
?>
--EXPECT--
defer [1]
timer [1]
defer [2]
timer [2]
