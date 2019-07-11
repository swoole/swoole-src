--TEST--
swoole_library/string_object: base
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';
$string = _string('www.swoole.com ')->rtrim();
$array = $string->split('.');
Assert::same($array->count(), 3);
Assert::same((string)$string->substr(_string($array[0])->length() + 1), 'swoole.com');
Assert::same((string)$string->upper(), 'WWW.SWOOLE.COM');
echo $string->upper()->substr(-8, 1) . 'K' . PHP_EOL;
Assert::same((string)$string, 'www.swoole.com');
?>
--EXPECT--
OK
