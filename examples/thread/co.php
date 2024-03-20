<?php
$map = new Swoole\Thread\Map(2);
$map['uuid'] = uniqid();

$t1 = Swoole\Thread::exec('mt.php', 'thread-1', PHP_OS, $map);
$t2 = Swoole\Thread::exec('mt.php', 'thread-2', PHP_OS, $map);

//var_dump($t1->id);
//var_dump($t2->id);
echo Swoole\Thread::getId() . "\t" . 'gmap[uuid]' . "\t" . $map['uuid'] . "\n";

$t1->join();
$t2->join();


