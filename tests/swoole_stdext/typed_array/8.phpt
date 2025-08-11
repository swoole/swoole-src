--TEST--
swoole_stdext/typed_array: 8
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

$arr = typed_array('<int>');

$arr[] = 1;
$arr[0] += 10;
Assert::eq($arr[0], 11);

try {
    $arr[0] .= "hello world";
} catch (TypeError $e) {
    Assert::true($e->getMessage()->contains('Array value type mismatch'));
    echo "DONE\n";
}

?>
--EXPECT--
DONE
