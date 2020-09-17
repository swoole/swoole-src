--TEST--
swoole_library/array_object: base
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';
$data = ['foo', 'bar', 'char' => 'dua'];
$array = _array();
Assert::true($array->isEmpty());
$array->__construct($data);
Assert::false($array->isEmpty());
Assert::same($array->__toArray(), $data);
Assert::same($array[0], $data[0]);
Assert::isIterable($array);
Assert::eq($array, _array()->unserialize($array->serialize()));
$array->push('OK');
$array->pushBack($array->pop());
echo $array->popBack() . PHP_EOL;
Assert::same($array->count(), count($data));
Assert::true($array->clear()->isEmpty());
Assert::isEmpty($array->__toArray());
?>
--EXPECT--
OK
