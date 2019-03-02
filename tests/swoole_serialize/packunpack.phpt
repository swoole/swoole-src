--TEST--
swoole_serialize: pack & unpack
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_class_not_exist('swoole_serialize');
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

// int
$int_data = mt_rand(100, 999);
$data = swoole_serialize::pack($int_data);
$un_data = swoole_serialize::unpack($data);
Assert::eq($int_data, $un_data);

// long
$long_data = mt_rand(100000000000, 999999999999);
$data = swoole_serialize::pack($long_data);
$un_data = swoole_serialize::unpack($data);
Assert::eq($long_data, $un_data);

// string
$str_data = str_repeat('bcy', 10);
$data = swoole_serialize::pack($str_data);
$un_data = swoole_serialize::unpack($data);
Assert::eq($str_data, $un_data);

// array
$arr_data = array_pad([], 32, '0123456789abcdefghijklmnopqrstuvwxyz');
$data = swoole_serialize::pack($arr_data);
$un_data = swoole_serialize::unpack($data);
Assert::eq($arr_data, $un_data);

// large array
$large_arr_data = array_pad([], 4096, '0123456789abcdefghijklmnopqrstuvwxyz');
$data = swoole_serialize::pack($large_arr_data);
$un_data = swoole_serialize::unpack($data);
Assert::eq($large_arr_data, $un_data);

// error array data
$data_out = substr($data, 0, 8192);
$err_data = @swoole_serialize::unpack($data_out);
Assert::false($err_data);
?>
DONE
--EXPECTF--
DONE
