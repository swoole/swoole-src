--TEST--
swoole_serialize: Check for null serialisation
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_class_not_exist('swoole_serialize');
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

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
