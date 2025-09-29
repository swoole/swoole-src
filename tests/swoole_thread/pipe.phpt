--TEST--
swoole_thread: pipe
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_nts();
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Thread;

$args = Thread::getArguments();

if (empty($args)) {
    $rdata = random_bytes(random_int(1024, 2048));
    Co\run(function () use ($rdata) {
        $sockets = swoole_coroutine_socketpair(STREAM_PF_UNIX, STREAM_SOCK_STREAM, STREAM_IPPROTO_IP);
        $thread = new Thread(__FILE__, $sockets[1], $rdata);
        Assert::eq($sockets[0]->recv(8192), $rdata);
        $thread->join();
        echo "DONE\n";
    });
} else {
    $socket = $args[0];
    $rdata = $args[1];
    Co\run(function () use ($socket, $rdata, $argv) {
        usleep(100);
        shell_exec('sleep 0.01');
        $socket->send($rdata);
    });
    exit(0);
}
?>
--EXPECTF--
DONE
