--TEST--
swoole_library/string_object: base
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';
$string = _string('www.swoole.com ')->rtrim();
$array = $string->split('.');
Assert::eq($array->count(), 3);
Assert::eq((string)$string->substr(_string($array[0])->length() + 1), 'swoole.com');
Assert::eq((string)$string->upper(), 'WWW.SWOOLE.COM');
echo $string->upper()->substr(-8, 1) . 'K' . PHP_EOL;
Assert::eq((string)$string, 'www.swoole.com');
?>
--EXPECT--
OK
