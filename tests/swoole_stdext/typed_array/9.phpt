--TEST--
swoole_stdext/typed_array: 9
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

$arr = typed_array('<int>', [1, 3, 5]);
array_push($arr, 7);
Assert::eq($arr[3], 7);

try {
    array_push($arr, 9, 'hello world', true);
} catch (TypeError $e) {
    Assert::true($e->getMessage()->contains('Array value type mismatch'));
    echo "DONE\n";
}
?>
--EXPECT--
DONE
