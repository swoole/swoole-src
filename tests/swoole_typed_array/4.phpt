--TEST--
swoole_stdext/typed_array: 4
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$array = typed_array('<int, string>');
$array[999] = 'test';

try {
    $array['hello'] = 'world';
} catch (TypeError $e) {
    Assert::true($e->getMessage()->contains('Array key type mismatch'));
    echo "DONE\n";
}

$key = str_repeat('a', 1000);
try {
    $array[$key] = 'world';
} catch (TypeError $e) {
    Assert::true($e->getMessage()->contains('Array key type mismatch'));
    echo "DONE\n";
}
?>
--EXPECTF--
DONE
DONE
