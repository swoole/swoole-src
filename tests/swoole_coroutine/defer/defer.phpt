--TEST--
swoole_coroutine/defer: coro defer
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';
go(function () {
    defer(function () {
        echo "10\n";
        assert(co::getuid() === 1);
        co::sleep(.001);
        assert(co::getuid() === 1);
        echo "11\n";
        defer(function () {
            echo "14\n";
            assert(co::getuid() === 1);
            co::sleep(.001);
            assert(co::getuid() === 1);
            echo "15\n";
        });
        defer(function () {
            echo "12\n";
            assert(co::getuid() === 1);
            co::sleep(.001);
            assert(co::getuid() === 1);
            echo "13\n";
        });
    });
    defer(function () {
        echo "8\n";
        assert(co::getuid() === 1);
        co::sleep(.001);
        assert(co::getuid() === 1);
        echo "9\n";
    });
    echo "0\n";
    assert(co::getuid() === 1);
    co::sleep(.001);
    assert(co::getuid() === 1);
    echo "1\n";
    defer(function () {
        echo "4\n";
        assert(co::getuid() === 1);
        co::sleep(.001);
        assert(co::getuid() === 1);
        echo "5\n";
        defer(function () {
            echo "6\n";
            assert(co::getuid() === 1);
            co::sleep(.001);
            assert(co::getuid() === 1);
            echo "7\n";
        });
    });
    defer(function () {
        echo "2\n";
        assert(co::getuid() === 1);
        co::sleep(.001);
        assert(co::getuid() === 1);
        echo "3\n";
    });
});
swoole_event_wait();
?>
--EXPECT--
0
1
2
3
4
5
6
7
8
9
10
11
12
13
14
15
