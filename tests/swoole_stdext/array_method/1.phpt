--TEST--
swoole_stdext/array_method: 1
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

$array = typed_array('<string>', ["lemon", "orange", "banana", "apple"]);
$sorted_array = array("apple", "banana", "lemon", "orange",);

$ref = &$array;
$ref->sort(SORT_NATURAL | SORT_FLAG_CASE);

Assert::same($array, $sorted_array);
Assert::same($ref, $sorted_array);
?>
--EXPECT--
