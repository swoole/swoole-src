--TEST--
swoole_coroutine: coro nested empty
--SKIPIF--
<?php require  __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

go(function () {
    echo "co[1] start\n";
    go(function () {
        echo "co[2] start\n";
        echo "co[2] exit\n";
    });
    echo "co[1] exit\n";
});
?>
--EXPECT--
co[1] start
co[2] start
co[2] exit
co[1] exit
