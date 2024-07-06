<?php
use Swoole\Thread;
$args = Thread::getArguments();

if (empty($args)) {
    $array = [
        'a' => random_int(1, 999999999999999999),
        'b' => random_bytes(128),
        'c' => uniqid(),
        'd' => time(),
    ];

    $map = new Thread\Map($array);
    $thread = new Thread(__FILE__, $map);
} else {
    $map = $args[0];
    var_dump($map->toArray());
}
