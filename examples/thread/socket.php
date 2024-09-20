<?php


use Swoole\Thread;
use Swoole\Thread\Lock;
use Swoole\Thread\Map;

$args = Thread::getArguments();

if (empty($args)) {
    $map = new Map();
    $sock = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
    $map['socket'] = $sock;
    $thread = new Thread(__FILE__, $map);
    echo "main thread\n";
    $thread->join();
} else {
    $map = $args[0];
    $sock = $map['socket'];
    $retval = socket_connect($sock, '127.0.0.1', 80);
}
