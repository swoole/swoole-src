--TEST--
swoole_thread: signal
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_nts();
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Process;
use Swoole\Thread;
use Swoole\Coroutine\System;
use Swoole\Timer;

$args = Thread::getArguments();

if (empty($args)) {
    Co\run(function () {
        $sockets = swoole_coroutine_socketpair(STREAM_PF_UNIX, STREAM_SOCK_STREAM, STREAM_IPPROTO_IP);
        $thread = new Thread(__FILE__, $sockets[0]);
        $parent_pipe = $sockets[1];
        Timer::after(500, function () {
            echo "timer\n";
            Process::kill(posix_getpid(), SIGTERM);
        });
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
    $child_pipe = $args[0];
    Co\run(function () use ($child_pipe) {
        // 收到父线程的指令，开始退出
        echo $child_pipe->recv(8192), PHP_EOL;
        // 通知父线程已退出
        $child_pipe->send('child exit');
    });
    exit(0);
}
?>
--EXPECTF--
timer
signal term
exit
child exit
