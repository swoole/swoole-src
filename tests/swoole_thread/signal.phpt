--TEST--
swoole_thread: signal
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
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
        global $argv;
        $sockets = swoole_coroutine_socketpair(STREAM_PF_UNIX, STREAM_SOCK_STREAM, STREAM_IPPROTO_IP);
        $thread = Thread::exec(__FILE__, $argv, $sockets);
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
    $argv = $args[0];
    $sockets = $args[1];
    $child_pipe = $sockets[0];
    Co\run(function () use ($child_pipe, $argv) {
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
