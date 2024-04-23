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
        global $argv;
        $sockets = swoole_coroutine_socketpair(STREAM_PF_UNIX, STREAM_SOCK_STREAM, STREAM_IPPROTO_IP);
        $thread = Thread::exec(__FILE__, $argv, $sockets, $rdata);
        Assert::eq($sockets[0]->recv(8192), $rdata);
        $thread->join();
        echo "DONE\n";
    });
} else {
    $argv = $args[0];
    $sockets = $args[1];
    $rdata = $args[2];
    // Child threads are not allowed to modify hook flags
    Assert::false(Swoole\Runtime::enableCoroutine(SWOOLE_HOOK_ALL));
    Co\run(function () use ($sockets, $rdata, $argv) {
        usleep(100);
        shell_exec('sleep 0.01');
        $sockets[1]->send($rdata);
    });
    exit(0);
}
?>
--EXPECTF--
DONE
