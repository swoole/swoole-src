--TEST--
swoole_stdext/typed_array: resource
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

$map = typed_array('<string, resource>');
$map['a'] = fopen(__FILE__, 'r');
Assert::eq(get_resource_type($map['a']), 'stream');

try {
    $map['b'] = 1;
} catch (Throwable $e) {
    Assert::true($e->getMessage()->contains('Array value type mismatch'));
    echo "DONE\n";
}
?>
--EXPECT--
DONE
