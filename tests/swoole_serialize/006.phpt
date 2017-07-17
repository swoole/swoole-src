--TEST--
Check for simple string serialization
--SKIPIF--
--FILE--
<?php

function test($type, $variable) {
    $serialized = swoole_serialize::pack($variable);
    $unserialized = swoole_serialize::unpack($serialized);

    echo $type, PHP_EOL;
    var_dump($unserialized);
    echo $unserialized === $variable ? 'OK' : 'ERROR', PHP_EOL;
}

test('empty: ""', "");
test('string: "foobar"', "foobar");
?>
--EXPECT--
empty: ""
string(0) ""
OK
string: "foobar"
string(6) "foobar"
OK
