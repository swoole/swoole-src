--TEST--
swoole_coroutine: coro nested strict
--SKIPIF--
<?php require  __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

Assert::eq(Co::getuid(), -1);
go(function () {
    Assert::eq(Co::getuid(), 1);
    Co::sleep(0.01);
    Assert::eq(Co::getuid(), 1);
});
Assert::eq(Co::getuid(), -1);
go(function () {
    Assert::eq(Co::getuid(), 2);

    go(function () {
        Assert::eq(Co::getuid(), 3);
        go(function () {
            Assert::eq(Co::getuid(), 4);
            go(function () {
                Assert::eq(Co::getuid(), 5);
                Co::sleep(0.01);
                Assert::eq(Co::getuid(), 5);
            });
            Assert::eq(Co::getuid(), 4);
        });
        Assert::eq(Co::getuid(), 3);
    });
    Assert::eq(Co::getuid(), 2);
});
Assert::eq(Co::getuid(), -1);
?>
--EXPECT--