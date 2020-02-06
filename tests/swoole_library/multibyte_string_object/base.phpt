--TEST--
swoole_library/multibyte_string_object: base
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

$str = swoole_mbstring('我是中国人');
var_dump((string) $str->substr(0));
var_dump((string) $str->substr(2, 2));
var_dump($str->contains('中国'));
var_dump($str->contains('美国'));
var_dump($str->startsWith('我'));
var_dump($str->endsWith('不是'));
var_dump($str->length());

?>
--EXPECT--
string(15) "我是中国人"
string(6) "中国"
bool(true)
bool(false)
bool(true)
bool(false)
int(5)
