--TEST--
swoole_coroutine: coro nested strict
--SKIPIF--
<?php require  __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

Assert::same(Co::getuid(), -1);
go(function () {
    Assert::same(Co::getuid(), 1);
    Co::sleep(0.01);
    Assert::same(Co::getuid(), 1);
});
Assert::same(Co::getuid(), -1);
go(function () {
    Assert::same(Co::getuid(), 2);

    go(function () {
        Assert::same(Co::getuid(), 3);
        go(function () {
            Assert::same(Co::getuid(), 4);
            go(function () {
                Assert::same(Co::getuid(), 5);
                Co::sleep(0.01);
                Assert::same(Co::getuid(), 5);
            });
            Assert::same(Co::getuid(), 4);
        });
        Assert::same(Co::getuid(), 3);
    });
    Assert::same(Co::getuid(), 2);
});
Assert::same(Co::getuid(), -1);
?>
--EXPECT--
