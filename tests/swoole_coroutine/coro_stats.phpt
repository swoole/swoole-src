--TEST--
swoole_coroutine: current stats
--SKIPIF--
<?php require  __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

assert(Co::stats()['coroutine_num'] === 0);
assert(Co::stats()['coroutine_peak_num'] === 0);
go(function () {
    assert(Co::stats()['coroutine_num'] === 1);
    assert(Co::stats()['coroutine_peak_num'] === 1);
    Co::sleep(0.5);
    assert(Co::stats()['coroutine_num'] === 2);
    assert(Co::stats()['coroutine_peak_num'] === 2);
});
go(function () {
    assert(Co::stats()['coroutine_num'] === 2);
    assert(Co::stats()['coroutine_peak_num'] === 2);
    Co::sleep(0.5);
    assert(Co::stats()['coroutine_num'] === 1);
    assert(Co::stats()['coroutine_peak_num'] === 2);
});
assert(Co::stats()['coroutine_num'] === 2);
assert(Co::stats()['coroutine_peak_num'] === 2);
?>
--EXPECT--