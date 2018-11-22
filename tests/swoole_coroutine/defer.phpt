--TEST--
swoole_coroutine: coro defer
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
go(function () {
    defer(function () {
        echo "4\n";
        co::sleep(.001);
        assert(co::getuid() === 1);
        echo "5\n";
        defer(function () {
            echo "8\n";
            co::sleep(.001);
            assert(co::getuid() === 1);
            echo "9\n";
        });
        defer(function () {
            echo "6\n";
            co::sleep(.001);
            assert(co::getuid() === 1);
            echo "7\n";
        });
    });
    defer(function () {
        echo "2\n";
        co::sleep(.001);
        assert(co::getuid() === 1);
        echo "3\n";
    });
    echo "0\n";
    co::sleep(.001);
    assert(co::getuid() === 1);
    echo "1\n";
});
swoole_event_wait();
?>
--EXPECT--
1
2
3
4
5
6
7
8
9
