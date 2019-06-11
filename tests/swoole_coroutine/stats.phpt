--TEST--
swoole_coroutine: current stats
--SKIPIF--
<?php require  __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

Assert::eq(Co::stats()['coroutine_num'], 0);
Assert::eq(Co::stats()['coroutine_peak_num'], 0);
go(function () {
    Assert::eq(Co::stats()['coroutine_num'], 1);
    Assert::eq(Co::stats()['coroutine_peak_num'], 1);
    Co::sleep(0.5);
    Assert::eq(Co::stats()['coroutine_num'], 2);
    Assert::eq(Co::stats()['coroutine_peak_num'], 2);
});
go(function () {
    Assert::eq(Co::stats()['coroutine_num'], 2);
    Assert::eq(Co::stats()['coroutine_peak_num'], 2);
    Co::sleep(0.5);
    Assert::eq(Co::stats()['coroutine_num'], 1);
    Assert::eq(Co::stats()['coroutine_peak_num'], 2);
});
Assert::eq(Co::stats()['coroutine_num'], 2);
Assert::eq(Co::stats()['coroutine_peak_num'], 2);
?>
--EXPECT--
