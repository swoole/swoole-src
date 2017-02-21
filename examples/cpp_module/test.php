<?php
$module = swoole_load_module(__DIR__.'/test.so');

ReflectionClass::export("CppClass");
// exit;
//var_dump($r);

CppClass::test("xxx");

$obj = new \CppClass;
var_dump($obj->name);
var_dump($obj->test2());
echo "Countable interface: ".count($obj)."\n";

$obj2 = new \CppClass;
var_dump($obj2->name);
var_dump($obj2->test2());
