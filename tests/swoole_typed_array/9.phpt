--TEST--
swoole_stdext/typed_array: 9
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$array = typed_array('<int, string>');
$array[999] = random_bytes(128);

try {
    $a = typed_array('<int, string>');
    $array[888] = $a;
} catch (TypeError $e) {
    Assert::true($e->getMessage()->contains('Array value type mismatch'));
    echo "DONE\n";
}

?>
--EXPECT--
DONE
