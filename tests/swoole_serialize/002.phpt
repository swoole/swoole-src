--TEST--
Check for null serialisation
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

test('null', null);
?>
--EXPECT--
null
NULL
OK
