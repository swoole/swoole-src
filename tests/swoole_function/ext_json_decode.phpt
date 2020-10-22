--TEST--
swoole_function: ext_json_decode
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
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
$rs = swoole_ext_json_decode($str, 4, $l, true);

Assert::eq($a, $rs);
?>
--EXPECT--
