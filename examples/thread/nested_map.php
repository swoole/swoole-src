<?php
$map = new Swoole\Thread\Map();

$map['map1'] = new Swoole\Thread\Map();
$map['list1'] = new Swoole\Thread\ArrayList();

$map['map1']['key1'] = 'value1';
$map['list1'][0] = 'value2';
$map['str'] = 'hello world';

$map['map2'] = [
    'a' => uniqid(),
    'b' => random_int(1000, 9999),
];

var_dump($map['map1']['key1']);
var_dump($map['list1'][0]);

var_dump($map['list1']->toArray());

var_dump($map['map2']);
