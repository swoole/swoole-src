<?php
//echo "begin\n";

$args = Swoole\Thread::getArguments();

$map = $args[2];
$list = $args[3];

echo Swoole\Thread::getId() . "\t" . 'gmap[uuid]' . "\t" . $map['uuid'] . "\n";
$map['hello'] = uniqid('swoole');
var_dump($map->keys());

$list[] = uniqid('swoole');
$list[count($list)] = uniqid('php');

var_dump($args);

echo Swoole\Thread::getId() . "\t" . 'glist[0]' . "\t" . $list[0] . "\n";
var_dump(count($list));

//if ($args[0] == 'thread-2') {
//    $t3 = new Swoole\Thread('mt.php', 'thread-3', PHP_OS);
//    $t3->join();
//}

//sleep(5);
//echo "end\n";
