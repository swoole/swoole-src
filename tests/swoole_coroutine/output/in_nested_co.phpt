--TEST--
swoole_coroutine: use ob_* in nest co
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require_once __DIR__ . '/../../include/bootstrap.php';
go(function () {
    ob_start();
    echo "2\n"; // [#1] yield
    go(function () {
        echo "1\n"; // [#2] output: 1
        co::sleep(0.001); // yield
        // [#4] resume
        ob_start(); // to buffer
        echo "4\n";
    }); // [#5] destroyed and output: 4
    echo "3\n";
}); // [#3] destroyed and output: 2 3
?>
--EXPECT--
1
2
3
4