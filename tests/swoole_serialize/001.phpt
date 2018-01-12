--TEST--
swoole_serialize: Check for null serialisation
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
  class Obj {
        var $a;
        var $b;

        function __construct($a, $b) {
            $this->a = $a;
            $this->b = $b;
        }
    };
    $f = new Obj(1,2);
    $unserialized = swoole_serialize::pack($f);
    file_put_contents("/tmp/swoole_seria_test", $unserialized);
echo "OK"
?>
--EXPECT--
OK
