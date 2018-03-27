--TEST--
swoole_serialize: Object test, __autoload
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

    
function test($type, $test) {
    $serialized = file_get_contents("/tmp/swoole_seria_test");
    $unserialized = swoole_serialize::unpack($serialized);

    echo $type, PHP_EOL;
     
    var_dump($unserialized);
    echo $test || $unserialized->b == 2 ? 'OK' : 'ERROR', PHP_EOL;
}

spl_autoload_register(function ($classname) {
    class Obj {
        var $a;
        var $b;

        function __construct($a, $b) {
            $this->a = $a;
            $this->b = $b;
        }
    }
});

test('autoload', false);
?>
--EXPECTF--
autoload
object(Obj)#%d (2) {
  ["a"]=>
  int(1)
  ["b"]=>
  int(2)
}
OK
