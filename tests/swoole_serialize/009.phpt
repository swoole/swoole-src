--TEST--
swoole_serialize: Check for reference serialization
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_class_not_exist('swoole_serialize');
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

ini_set("display_errors", "Off");

function test($type, $variable, $test) {
  //  $serialized = serialize($variable);
//    $unserialized = unserialize($serialized);

    $serialized = swoole_serialize::pack($variable);
    $unserialized = swoole_serialize::unpack($serialized);
    echo $type, PHP_EOL;
    var_dump($unserialized);
    echo $test || $unserialized == $variable ? 'OK' : 'ERROR', PHP_EOL;
}

$a = array('foo');

test('array($a, $a)', array($a, $a), false);
test('array(&$a, &$a)', array(&$a, &$a), false);

$a = [];
$b = array(&$a);
$a[0] = &$b;

test('cyclic', $a, true);
?>
--EXPECT--
array($a, $a)
array(2) {
  [0]=>
  array(1) {
    [0]=>
    string(3) "foo"
  }
  [1]=>
  array(1) {
    [0]=>
    string(3) "foo"
  }
}
OK
array(&$a, &$a)
array(2) {
  [0]=>
  array(1) {
    [0]=>
    string(3) "foo"
  }
  [1]=>
  array(1) {
    [0]=>
    string(3) "foo"
  }
}
OK
cyclic
array(1) {
  [0]=>
  array(1) {
    [0]=>
    array(1) {
      [0]=>
      NULL
    }
  }
}
OK