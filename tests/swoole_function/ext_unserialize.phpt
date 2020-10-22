--TEST--
swoole_function: ext_unserialize
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$a['hello'] = base64_encode(random_bytes(1000));
$a['world'] = 'hello';
$a['int'] = rand(1, 999999);
$a['list'] = ['a,', 'b', 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'];

$val = serialize($a);
$str = pack('N', strlen($val)).$val."\r\n";

$l = strlen($str) - 6;
Assert::eq($a, swoole_ext_unserialize($str, 4, $l));
Assert::eq($a, swoole_ext_unserialize($str, 4));

?>
--EXPECT--
