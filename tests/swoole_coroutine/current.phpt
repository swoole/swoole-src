--TEST--
swoole_coroutine: current cid
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
assert(Co::getuid() === -1);
go(function () {
    assert(Co::getuid() === 1);
    Co::sleep(0.001);
    assert(Co::getuid() === 1);
    echo "DONE\n";
});
go(function () {
    assert(Co::getuid() === 2);
});
assert(Co::getuid() === -1);
?>
--EXPECT--
DONE
