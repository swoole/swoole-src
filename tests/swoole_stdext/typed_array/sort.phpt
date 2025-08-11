--TEST--
swoole_stdext/typed_array: sort
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

$arr = typed_array('<int>', [1243, 3434, 5453, 4532, 2, 3454, 5233, 655, 234, 6, 2356, 4554]);
Assert::true($arr->isList());
Assert::true($arr->isTyped());

sort($arr);
Assert::true($arr->isTyped());

shuffle($arr);
Assert::true($arr->isTyped());

?>
--EXPECT--
