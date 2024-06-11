<?php

use Swoole\Thread;
use Swoole\Coroutine\System;

$args = Thread::getArguments();

if (empty($args)) {
    Co\run(function () {
        echo "main thread\n";
        $sockets = swoole_coroutine_socketpair(STREAM_PF_UNIX, STREAM_SOCK_STREAM, STREAM_IPPROTO_IP);
        $thread = new Thread(__FILE__, $sockets);
        $parent_pipe = $sockets[1];
        // 收到信号之后向子线程发送指令让子线程退出
        if (System::waitSignal(SIGTERM)) {
            echo "signal term\n";
            $parent_pipe->send('exit');
        }
        Co\go(function () use ($parent_pipe, $thread) {
            // 从管道中读取子线程退出的信息
            echo $parent_pipe->recv(8192), PHP_EOL;
            // 回收子线程
            $thread->join();
        });
    });
} else {
    echo "child thread\n";
    $sockets = $args[0];
    $child_pipe = $sockets[0];
    Co\run(function () use ($child_pipe) {
        // 收到父线程的指令，开始退出
        echo $child_pipe->recv(8192), PHP_EOL;
        // 通知父线程已退出
        $child_pipe->send('child exit');
    });
}
