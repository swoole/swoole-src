--TEST--
Test of swoole_serialize pack_unpack
--SKIPIF--
<?php include "skipif.inc"; ?>
--FILE--
<?php
//TODO: finish simple type test

// Large Array
$ret = array_pad([], 4096, '0123456789abcdefghijklmnopqrstuvwxyz');

$data = swoole_serialize::pack($ret);
echo strlen($data), "\n";
$un_data = swoole_serialize::unpack($data);
echo count($un_data), "\n";

// error array data
$data_out = substr($data, 0, 8192);
$un_data = swoole_serialize::unpack($data);
echo $un_data?1:0, "\n";

?>
Done
--EXPECTREGEX--
12326
4096
1
--CLEAN--
