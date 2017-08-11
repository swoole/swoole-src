--TEST--
swoole_serialize: Object test
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
    public $a;
    protected $b;
    private $c;

    function __construct($a, $b, $c) {
        $this->a = $a;
        $this->b = $b;
        $this->c = $c;
    }
}

$o = new Obj(1, 2, 3);


test('object', $o, false);
?>
--EXPECTF--
object
object(Obj)#%d (3) {
  ["a"]=>
  int(1)
  [%r"?b"?:protected"?%r]=>
  int(2)
  [%r"?c"?:("Obj":)?private"?%r]=>
  int(3)
}
OK
