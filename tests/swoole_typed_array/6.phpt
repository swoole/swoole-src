--TEST--
swoole_stdext/typed_array: 6
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$num = random_int(1, 1000);
$array = typed_array('<int>', [1, $num, 3]);
Assert::eq($array->count(), 3);
Assert::eq($array[1], $num);

try {
    $array = typed_array('<int>', [1, "hello", 3]);
} catch (Throwable $e) {
    Assert::true($e->getMessage()->contains('Array value type mismatch'));
    echo "DONE\n";
}
?>
--EXPECT--
DONE
