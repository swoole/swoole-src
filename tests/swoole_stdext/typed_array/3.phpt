--TEST--
swoole_stdext/typed_array: 3
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

$map = typed_array('<string, int>');
$map['a'] = 1;
$map['b'] = 2;
$map['c'] = 3;
unset($map['b']);

Assert::true(isset($map['a']));
Assert::true(isset($map['c']));
Assert::false(isset($map['b']));

$array = typed_array('<int>');
$array[] = 3;
$array[] = 5;
$array[] = 7;

try {
    unset($array[0]);
} catch (Throwable $e) {
    Assert::true($e->getMessage()->contains('not support'));
    echo "DONE\n";
}
?>
--EXPECT--
DONE
