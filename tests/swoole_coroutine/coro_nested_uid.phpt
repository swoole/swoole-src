--TEST--
swoole_coroutine: coro nested strict
--SKIPIF--
<?php require  __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require_once __DIR__ . '/../include/bootstrap.php';

assert(Co::getuid() === -1);
go(function () {
    assert(Co::getuid() === 1);
    Co::sleep(0.01);
    assert(Co::getuid() === 1);
});
assert(Co::getuid() === -1);
go(function () {
    assert(Co::getuid() === 2);
   
    go(function () {
        assert(Co::getuid() === 3);
        go(function () {
            assert(Co::getuid() === 4);
            go(function () {
                assert(Co::getuid() === 5);
                Co::sleep(0.01);
                assert(Co::getuid() === 5);
            });
            assert(Co::getuid() === 4);
        });
        assert(Co::getuid() === 3);
    });
    assert(Co::getuid() === 2);
});
assert(Co::getuid() === -1);
?>
--EXPECT--