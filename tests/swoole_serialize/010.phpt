--TEST--
swoole_serialize: Array test
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
function test($type, $variable, $test) {
    $serialized = swoole_serialize::pack($variable);
    $unserialized = swoole_serialize::unpack($serialized);

    echo $type, PHP_EOL;
    var_dump($unserialized);
    echo $test || $unserialized == $variable ? 'OK' : 'ERROR', PHP_EOL;
}

$a = array(
    'a' => array(
        'b' => 'c',
        'd' => 'e'
    ),
    'f' => array(
        'g' => 'h'
    )
);

test('array', $a, false);
?>
--EXPECT--
array
array(2) {
  ["a"]=>
  array(2) {
    ["b"]=>
    string(1) "c"
    ["d"]=>
    string(1) "e"
  }
  ["f"]=>
  array(1) {
    ["g"]=>
    string(1) "h"
  }
}
OK
