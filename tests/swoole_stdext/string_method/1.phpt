--TEST--
swoole_stdext/string_method: 1
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

$str = "first=value&arr[]=foo+bar&arr[]=baz";

$output = $str->parseStr();
Assert::eq($output['first'], 'value');
Assert::eq($output['arr'][0], 'foo bar');
Assert::eq($output['arr'][1], 'baz');
?>
--EXPECT--
