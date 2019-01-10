--TEST--
swoole_serialize: Object test, type undef
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_class_not_exist('swoole_serialize');
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

ini_set("display_errors", "Off");
class Foo
{
    public $a = 'a';
}

$foo = new Foo();
$foo->a = 'b';
unset($foo->a);
$ser = swoole_serialize::pack($foo);
$bar = swoole_serialize::unpack($ser);
var_dump($bar);

?>
--EXPECTF--
object(Foo)#%d (1) {
  ["a"]=>
  NULL
}
