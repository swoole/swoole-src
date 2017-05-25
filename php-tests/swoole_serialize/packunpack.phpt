--TEST--
Test of swoole_serialize pack_unpack
--SKIPIF--
<?php include "skipif.inc"; ?>
--FILE--
<?php
// int
$int_data = mt_rand(100,999);
$data = swoole_serialize::pack($int_data);
$un_data = swoole_serialize::unpack($data);
var_dump($int_data);

// long
$long_data = mt_rand(100000000000,999999999999);
$data = swoole_serialize::pack($long_data);
$un_data = swoole_serialize::unpack($data);
var_dump($long_data);

// string
$str_data = str_repeat('bcy', 10);
$data = swoole_serialize::pack($str_data);
$un_data = swoole_serialize::unpack($data);
var_dump(strlen($str_data));

// array
$arr_data = array_pad([], 32, '0123456789abcdefghijklmnopqrstuvwxyz');
$data = swoole_serialize::pack($arr_data);
$un_data = swoole_serialize::unpack($data);
var_dump(count($arr_data));

// large array
$large_arr_data = array_pad([], 4096, '0123456789abcdefghijklmnopqrstuvwxyz');

$data = swoole_serialize::pack($large_arr_data);
var_dump(strlen($data));
$un_data = swoole_serialize::unpack($data);
var_dump(count($un_data));

// error array data
$data_out = substr($data, 0, 8192);
$err_data = swoole_serialize::unpack($data_out);
var_dump($err_data);
?>
===DONE===
<?php exit(0); ?>
--EXPECTF--
int(%d)
int(%d)
int(30)
int(32)
int(12326)
int(4096)

Notice: Swoole\Serialize::unpack(): illegal unserialize data in %s on line %d

Notice: Swoole\Serialize::unpack(): illegal array unserialize data in %s on line %d
bool(false)
===DONE===
