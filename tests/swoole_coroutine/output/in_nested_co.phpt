--TEST--
swoole_coroutine/output: use ob_* in nest co
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';
go(function () {
    ob_start();
    echo "2\n"; // [#1] yield
    go(function () {
        echo "1\n"; // [#2] output: 1
        co::fgets(fopen(__FILE__, 'r')); // yield
        // [#4] resume
        ob_start(); // to buffer
        echo "4\n";
    }); // [#5] destroyed and output: 4
    echo "3\n";
}); // [#3] destroyed and output: 2 3
swoole_event_wait();
?>
--EXPECT--
1
2
3
4
