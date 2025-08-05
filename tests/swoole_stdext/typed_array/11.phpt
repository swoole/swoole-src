--TEST--
swoole_stdext/typed_array: 11
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

$num = random_int(1, 1000);
$array = typed_array('<int>', [1, $num, 3]);
foreach($array as &$v) {
    var_dump($v);
    echo "each\n";
}
echo "end\n";
?>
--EXPECTF--
Fatal error: Uncaught Error: The type array do not support using references for element value during iteration in %s:%d
Stack trace:
#0 {main}
  thrown in %s on line %d
