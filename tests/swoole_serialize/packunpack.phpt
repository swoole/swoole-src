--TEST--
swoole_serialize: pack & unpack
--SKIPIF--
<?php
require __DIR__ . "/../include/skipif.inc";
if (!class_exists("swoole_serialize", false))
{
    echo "skip";
}
?>
--INI--
assert.active=1
assert.warning=1
assert.bail=0
assert.quiet_eval=0

--FILE--
<?php
// int
$int_data = mt_rand(100, 999);
$data = swoole_serialize::pack($int_data);
$un_data = swoole_serialize::unpack($data);
assert($int_data == $un_data);

// long
$long_data = mt_rand(100000000000, 999999999999);
$data = swoole_serialize::pack($long_data);
$un_data = swoole_serialize::unpack($data);
assert($long_data == $un_data);

// string
$str_data = str_repeat('bcy', 10);
$data = swoole_serialize::pack($str_data);
$un_data = swoole_serialize::unpack($data);
assert($str_data == $un_data);

// array
$arr_data = array_pad([], 32, '0123456789abcdefghijklmnopqrstuvwxyz');
$data = swoole_serialize::pack($arr_data);
$un_data = swoole_serialize::unpack($data);
assert($arr_data == $un_data);

// large array
$large_arr_data = array_pad([], 4096, '0123456789abcdefghijklmnopqrstuvwxyz');
$data = swoole_serialize::pack($large_arr_data);
$un_data = swoole_serialize::unpack($data);
assert($large_arr_data == $un_data);

// error array data
$data_out = substr($data, 0, 8192);
$err_data = @swoole_serialize::unpack($data_out);
assert($err_data == false);
?>
DONE
--EXPECTF--
DONE
