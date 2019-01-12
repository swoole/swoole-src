--TEST--
swoole_serialize: Object test, stdclass
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_class_not_exist('swoole_serialize');
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

ini_set("display_errors", "Off");
function test($variable, $test) {
 $serialized = swoole_serialize::pack($variable);
    $unserialized = swoole_serialize::unpack($serialized, UNSERIALIZE_OBJECT_TO_STDCLASS);

    echo UNSERIALIZE_OBJECT_TO_STDCLASS, PHP_EOL;

    var_dump($unserialized);
    echo get_class($unserialized->sub) == "stdClass" ? 'OK' : 'ERROR', PHP_EOL;
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
2
object(stdClass)#%d (1) {
  ["sub"]=>
  object(stdClass)#%d (1) {
    ["b"]=>
    string(3) "sub"
  }
}
OK
