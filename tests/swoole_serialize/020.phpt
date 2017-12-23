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
function test($variable, $test) {
    $unserialized = swoole_serialize::unpack($variable, UNSERIALIZE_OBJECT_TO_STDCLASS);

    echo UNSERIALIZE_OBJECT_TO_STDCLASS, PHP_EOL;
     
    var_dump($unserialized);
    echo $test || get_class($unserialized) == "stdClass" ? 'OK' : 'ERROR' || get_class($unserialized->sub) == "stdClass" ? 'OK' : 'ERROR', PHP_EOL;
}

class Obj {
    var $sub;
}

class subObj {
    var $b = "sub";
}

$o = new Obj();
$o->sub = new subObj();

test($o, true);
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
