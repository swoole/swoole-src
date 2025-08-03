--TEST--
swoole_stdext/typed_array: 2
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$array = typed_array('<int, <string, string>>');
$array[999] = typed_array('<string, string>');

try {
    $array[888] = typed_array('<int, string>');
} catch (TypeError $e) {
    Assert::true($e->getMessage()->contains('Array value type mismatch'));
    echo "DONE\n";
}

try {
    $array[777] = [];
} catch (TypeError $e) {
    Assert::true($e->getMessage()->contains('Array value type mismatch'));
    echo "DONE\n";
}

?>
--EXPECT--
DONE
DONE
