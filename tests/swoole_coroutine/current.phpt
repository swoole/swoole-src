--TEST--
swoole_coroutine: current cid
--SKIPIF--
<?php require  __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require_once __DIR__ . '/../include/bootstrap.php';
assert(Co::getuid() === -1);
go(function () {
    assert(Co::getuid() === 1);
    Co::sleep(1);
    assert(Co::getuid() === 1);
});
go(function () {
    assert(Co::getuid() === 2);
});
assert(Co::getuid() === -1);
?>
--EXPECT--