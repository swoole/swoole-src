--TEST--
swoole_stdext/string_method: marshal
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

$array = ['a' => random_bytes(128)->base64Encode(), 'b' => random_int(1, PHP_INT_MAX), 'c' => php_uname()];

$str = $array->marshal();
Assert::notEmpty($str);
Assert::eq($str->unmarshal(), $array);
?>
--EXPECT--
