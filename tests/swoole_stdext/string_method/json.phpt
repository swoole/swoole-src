--TEST--
swoole_stdext/string_method: json
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

$array = ['a' => random_bytes(128)->base64Encode(), 'b' => random_int(1, PHP_INT_MAX), 'c' => php_uname()];

$str = $array->jsonEncode();
Assert::notEmpty($str);
Assert::eq($str->jsonDecode(), $array);
?>
--EXPECT--
