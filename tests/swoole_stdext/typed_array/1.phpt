--TEST--
swoole_stdext/typed_array: 1
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

$array = typed_array('<int>');
$array[] = 123;

try {
    $array[] = "456";
} catch (TypeError $e) {
    $e->getMessage()->contains('Array value type mismatch');
}

$array = typed_array('<bool>');
$array[] = true;
$array[] = false;
try {
    $array[] = "456";
} catch (TypeError $e) {
    $e->getMessage()->contains('Array value type mismatch');
}

$array = typed_array('<string>');
$array[] = "456";
try {
    $array[] = true;
} catch (TypeError $e) {
    $e->getMessage()->contains('Array value type mismatch');
}

$array = typed_array('<float>');
$array[] = 4556.56;
try {
    $array[] = 456;
} catch (TypeError $e) {
    $e->getMessage()->contains('Array value type mismatch');
}

$array = typed_array('<stdClass>');
$array[] = new stdClass();
try {
    $array[] = new ArrayObject();
} catch (TypeError $e) {
    $e->getMessage()->contains('Array value type mismatch');
}

?>
--EXPECTF--
