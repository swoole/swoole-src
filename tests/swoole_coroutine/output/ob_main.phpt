--TEST--
swoole_coroutine/output: main output global
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';
ob_start();
echo 'aaa';
go(function () {
    ob_start();
    echo 'bbb';
    co::fgets(fopen(__FILE__, 'r'));
    Assert::eq(ob_get_clean(), 'bbb');
});
Assert::eq(ob_get_clean(), 'aaa');
?>
--EXPECT--
