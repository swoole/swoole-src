--TEST--
swoole_serialize: Object-Reference test
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

class Obj {
    var $a;
    var $b;

    function __construct($a, $b) {
        $this->a = $a;
        $this->b = $b;
    }
}

$o = new Obj(1, 2);
$a = array(&$o, &$o);

test('object', $a, false);
?>
--EXPECTF--
object
array(2) {
  [0]=>
  object(Obj)#%d (2) {
    ["a"]=>
    int(1)
    ["b"]=>
    int(2)
  }
  [1]=>
  object(Obj)#%d (2) {
    ["a"]=>
    int(1)
    ["b"]=>
    int(2)
  }
}
OK
