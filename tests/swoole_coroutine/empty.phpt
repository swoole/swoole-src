--TEST--
swoole_coroutine: coro empty
--SKIPIF--
<?php require  __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

go(function () {
    echo "co[1] start\n";
    echo "co[1] exit\n";
});
?>
--EXPECT--
co[1] start
co[1] exit
