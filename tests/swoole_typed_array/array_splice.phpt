--TEST--
swoole_stdext/typed_array: array_splice
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$arr = typed_array('<string>', array("red", "green", "blue", "yellow"));
array_splice($arr, 2);
Assert::eq($arr->count(), 2);
array_push($arr, "purple", "orange");
Assert::eq($arr->count(), 4);
Assert::true($arr->isList());

array_splice($arr, 1, count($arr), "black");
Assert::true($arr->contains("black"));
Assert::eq($arr->count(), 2);
Assert::true($arr->isList());
Assert::true($arr->isTyped());

array_splice($arr, -1, 1, array("gray", "maroon"));
Assert::eq($arr->count(), 3);
Assert::true($arr->contains("maroon"));
Assert::true($arr->isTyped());
Assert::true($arr->isList());

try {
    array_splice($arr, -1, 1, array(9999, false));
} catch (TypeError $e) {
    Assert::true($e->getMessage()->contains('Array value type mismatch'));
    echo "DONE\n";
}
?>
--EXPECT--
DONE
