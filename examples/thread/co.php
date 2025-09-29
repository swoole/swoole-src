<?php
$map = new Swoole\Thread\Map(2);
$map['uuid'] = uniqid();
$map[time()] = uniqid();

$list = new Swoole\Thread\ArrayList();
$list[] = base64_encode(random_bytes(32));
$list[1] = uniqid();
var_dump(count($list));

$t1 = new Swoole\Thread('mt.php', 'thread-1', PHP_OS, $map, $list);
$t2 = new Swoole\Thread('mt.php', 'thread-2', PHP_OS, $map, $list);

//var_dump($t1->id);
//var_dump($t2->id);
echo Swoole\Thread::getId() . "\t" . 'gmap[uuid]' . "\t" . $map['uuid'] . "\n";

try {
    var_dump($list[999]);
} catch (Swoole\Exception $e) {
    assert(str_contains($e->getMessage(), 'out of range'));
}

try {
    unset($list[0]);
} catch (Swoole\Exception $e) {
    assert(str_contains($e->getMessage(), 'unsupported'));
}

$t1->join();
$t2->join();


