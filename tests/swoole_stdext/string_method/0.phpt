--TEST--
swoole_stdext/string_method: 0
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

$string = "hello world, this is a test string";
Assert::false($string->isEmpty());
Assert::eq($string->length(), strlen($string));
Assert::eq($string->substr(0, 5), "hello");
Assert::eq($string->contains("world"), true);
Assert::eq($string->indexOf("test"), strpos($string, "test"));
Assert::eq($string->split(" "), explode(" ", $string));
Assert::true(""->isEmpty());
?>
--EXPECT--
