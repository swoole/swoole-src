--TEST--
swoole_function: substr_json_decode
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc';
skip_if_function_not_exist('swoole_substr_json_decode');
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$a['hello'] = base64_encode(random_bytes(1000));
$a['world'] = 'hello';
$a['int'] = rand(1, 999999);
$a['list'] = ['a,', 'b', 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'];

$val = json_encode($a);
$str = pack('N', strlen($val)).$val."\r\n";

$l = strlen($str) - 6;
Assert::eq(swoole_substr_json_decode($str, 4, 0, true), $a);
Assert::eq(@swoole_substr_json_decode($str, 0, -1, true), false);
Assert::eq(@swoole_substr_json_decode($str, 6, 0, true), false);
Assert::eq(@swoole_substr_json_decode($str, strlen($str) + 10, 0, true), false);
Assert::eq(@swoole_substr_json_decode($str, - (strlen($str) + 5), 0, true), false);
// offset is negative
Assert::eq(swoole_substr_json_decode($str, -(strlen($str)-4), $l, true), $a);
?>
--EXPECT--
