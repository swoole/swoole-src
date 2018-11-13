--TEST--
swoole_serialize: Check for double serialisation
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_class_not_exist('swoole_serialize');
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

function test($type, $variable) {
    $serialized = swoole_serialize::pack($variable);
    $unserialized = swoole_serialize::unpack($serialized);

    echo $type, PHP_EOL;
    var_dump($unserialized);
    echo $unserialized === $variable ? 'OK' : 'ERROR', PHP_EOL;
}

test('double: 123.456', 123.456);
?>
--EXPECT--
double: 123.456
float(123.456)
OK
