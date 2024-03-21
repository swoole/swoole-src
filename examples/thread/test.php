<?php
$map = new Swoole\Thread\Map(2);
echo "1\n";
$map['uuid'] = uniqid();

echo "2\n";
$map['uuid'] = uniqid();

$o = new stdClass();;
$o->uuid = uniqid();
$map['obj'] = $o;

var_dump($map['obj']);

$s = serialize($map);
var_dump(unserialize($s));

