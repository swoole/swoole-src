--TEST--
swoole_coroutine/output: main output global
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';
ob_start();
echo "0\n";
go(function () {
    ob_start();
    echo "1\n";
    go(function () {
        ob_start();
        echo "2\n";
    }); // close 2
});// close 1
// close 0
?>
--EXPECT--
2
1
0
