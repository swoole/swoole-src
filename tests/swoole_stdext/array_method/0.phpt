--TEST--
swoole_stdext/array_method: 0
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

$array = typed_array('<int>');
$array[0] = 1;
$array[1] = 2;
$array[2] = 3;
$array[3] = 999;
Assert::false($array->isEmpty());
Assert::eq($array->count(), count($array));
Assert::eq($array->slice(0, 2), [1, 2]);
Assert::true($array->contains(999));
Assert::eq($array->search(999), 3);
Assert::true([]->isEmpty());
?>
--EXPECT--
