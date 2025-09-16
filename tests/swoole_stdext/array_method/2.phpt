--TEST--
swoole_stdext/array_method: 2
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

$array = array("orange", "banana", "apple", "raspberry");

$stack = $array;
Assert::eq($stack->count(), 4);
$ref = &$stack;
$fruit = $ref->shift();
Assert::eq($fruit, "orange");
Assert::eq($stack->count(), 3);
Assert::eq($array->count(), 4);

$ref->unshift("mango");
Assert::eq($stack->count(), 4);

$stack2 = array("orange", "banana", "apple", "raspberry");
Assert::eq($stack2->count(), 4);
$stack2->shift();
?>
--EXPECTF--
Warning: array_shift(): Argument #1 ($array) must be passed by reference, value given in %s on line %d
