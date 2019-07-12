--TEST--
swoole_coroutine: current cid
--SKIPIF--
<?php require  __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
Assert::same(Co::getuid(), -1);
go(function () {
    Assert::same(Co::getuid(), 1);
    Co::sleep(1);
    Assert::same(Co::getuid(), 1);
});
go(function () {
    Assert::same(Co::getuid(), 2);
});
Assert::same(Co::getuid(), -1);
?>
--EXPECT--
