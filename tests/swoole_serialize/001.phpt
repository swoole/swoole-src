--TEST--
Check for null serialisation
--SKIPIF--
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
