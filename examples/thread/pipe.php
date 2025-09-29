<?php

use Swoole\Thread;

$args = Thread::getArguments();

if (empty($args)) {
    Co\run(function () {
        $sockets = swoole_coroutine_socketpair(STREAM_PF_UNIX, STREAM_SOCK_STREAM, STREAM_IPPROTO_IP);
        $thread = new Thread(__FILE__, $sockets);
        echo $sockets[0]->recv(8192), PHP_EOL;
        $thread->join();
    });
} else {
    $sockets = $args[0];
    Co\run(function () use ($sockets) {
        sleep(1);
        $sockets[1]->send(uniqid());
    });
}
