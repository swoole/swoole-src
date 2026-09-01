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
        if (IS_WIN) {
            $server = new Swoole\Coroutine\Socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            Assert::true($server->bind('127.0.0.1', 0));
            Assert::true($server->listen());
            $address = $server->getsockname();
            $client = new Swoole\Coroutine\Socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            Assert::true($client->connect('127.0.0.1', $address['port']));
            $peer = $server->accept();
            Assert::isInstanceOf($peer, Swoole\Coroutine\Socket::class);
            $server->close();
            $sockets = [$client, $peer];
        } else {
            $sockets = swoole_coroutine_socketpair(STREAM_PF_UNIX, STREAM_SOCK_STREAM, STREAM_IPPROTO_IP);
        }
        $thread = new Thread(__FILE__, $sockets[1], $rdata);
        Assert::eq($sockets[0]->recv(8192), $rdata);
        $thread->join();
        Assert::same($thread->getExitStatus(), 0);
        echo "DONE\n";
    });
} else {
    $socket = $args[0];
    $rdata = $args[1];
    Co\run(function () use ($socket, $rdata, $argv) {
        usleep(100);
        if (IS_WIN) {
            usleep(10000);
        } else {
            shell_exec(escapeshellarg(PHP_BINARY) . ' -r "usleep(10000);"');
        }
        $socket->send($rdata);
    });
    exit(0);
}
?>
--EXPECTF--
DONE
