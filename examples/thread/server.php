<?php

use Swoole\Thread;
use Swoole\Thread\Queue;

$args = Thread::getArguments();
$c = 2;
$running = true;

if (empty($args)) {
    $threads = [];
    $queue = new Queue;
    for ($i = 0; $i < $c; $i++) {
        $threads[] = new Thread(__FILE__, $i, $queue);
    }
    for ($i = 0; $i < $c; $i++) {
        $threads[$i]->join();
    }
} else {
    $http = new Swoole\Http\Server("0.0.0.0", 9503);
    $http->on('request', function ($req, Swoole\Http\Response $resp) {
        $resp->end('hello world');
    });
    $http->start();
}
