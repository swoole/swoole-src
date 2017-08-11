--TEST--
swoole_serialize: Check for integer serialisation
--SKIPIF--
<?php
require __DIR__ . "/../include/skipif.inc";
if (!class_exists("swoole_serialize", false))
{
    echo "skip";
}
?>
--FILE--
<?php

function test($type, $variable) {
    $serialized = swoole_serialize::pack($variable);
    $unserialized = swoole_serialize::unpack($serialized);

    echo $type, PHP_EOL;
    var_dump($unserialized);
    echo $unserialized === $variable ? 'OK' : 'ERROR', PHP_EOL;
}

test('zero: 0', 0);
test('small: 1',  1);
test('small: -1',  -1);
test('medium: 1000', 1000);
test('medium: -1000', -1000);
test('large: 100000', 100000);
test('large: -100000', -100000);
?>
--EXPECT--
zero: 0
int(0)
OK
small: 1
int(1)
OK
small: -1
int(-1)
OK
medium: 1000
int(1000)
OK
medium: -1000
int(-1000)
OK
large: 100000
int(100000)
OK
large: -100000
int(-100000)
OK
