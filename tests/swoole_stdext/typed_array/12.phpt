--TEST--
swoole_stdext/typed_array: 12
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

$arr = typed_array('<int>', [1, 3, 5, 7]);
$v = array_shift($arr);
Assert::eq($v, 1);
Assert::eq($arr[1], 5);
Assert::eq($arr->count(), 3);

try {
    array_unshift($arr, 9, 'hello world', true);
} catch (TypeError $e) {
    Assert::true($e->getMessage()->contains('Array value type mismatch'));
    echo "DONE\n";
}
?>
--EXPECT--
DONE
