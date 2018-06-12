--TEST--
swoole_serialize: Object test, type undef
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
if (!class_exists("swoole_serialize", false))
{
    echo "skip";
}
?>
--FILE--
<?php
require_once __DIR__ . '/../include/bootstrap.php';

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
object(Foo)#2 (1) {
  ["a"]=>
  NULL
}
