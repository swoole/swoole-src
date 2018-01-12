--TEST--
swoole_serialize: Object test, __wakeup
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
    echo $test || $unserialized->b == 3 ? 'OK' : 'ERROR', PHP_EOL;
}

class Obj {
    var $a;
    var $b;

    function __construct($a, $b) {
        $this->a = $a;
        $this->b = $b;
    }

    function __wakeup() {
        $this->b = $this->a * 3;
    }
}

$o = new Obj(1, 2);


test('object', $o, false);
?>
--EXPECTF--
object
object(Obj)#%d (2) {
  ["a"]=>
  int(1)
  ["b"]=>
  int(3)
}
OK
