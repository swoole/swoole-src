--TEST--
swoole_serialize: Check for array+string serialization
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

function test($type, $variable) {
    $serialized = swoole_serialize::pack($variable);
    $unserialized = swoole_serialize::unpack($serialized);

    echo $type, PHP_EOL;
    var_dump($unserialized);
    echo $unserialized == $variable ? 'OK' : 'ERROR', PHP_EOL;
}

test('array("foo", "foo", "foo")', array("foo", "foo", "foo"));
test('array("one" => 1, "two" => 2))', array("one" => 1, "two" => 2));
test('array("kek" => "lol", "lol" => "kek")', array("kek" => "lol", "lol" => "kek"));
test('array("" => "empty")', array("" => "empty"));
?>
--EXPECT--
array("foo", "foo", "foo")
array(3) {
  [0]=>
  string(3) "foo"
  [1]=>
  string(3) "foo"
  [2]=>
  string(3) "foo"
}
OK
array("one" => 1, "two" => 2))
array(2) {
  ["one"]=>
  int(1)
  ["two"]=>
  int(2)
}
OK
array("kek" => "lol", "lol" => "kek")
array(2) {
  ["kek"]=>
  string(3) "lol"
  ["lol"]=>
  string(3) "kek"
}
OK
array("" => "empty")
array(1) {
  [""]=>
  string(5) "empty"
}
OK
