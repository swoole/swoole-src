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
    if (IS_WIN) {
        Co::set(['hook_flags' => 0]);
    }
    Co\run(function () use ($rdata) {
        if (IS_WIN) {
            $server = stream_socket_server('tcp://127.0.0.1:0', $errno, $errstr);
            Assert::notEmpty($server);
            $address = stream_socket_get_name($server, false);
            $client = stream_socket_client("tcp://{$address}", $errno, $errstr, 5);
            Assert::notEmpty($client);
            $peer = stream_socket_accept($server, 5);
            Assert::notEmpty($peer);
            fclose($server);
            $sockets = [$client, $peer];
        } else {
            $sockets = swoole_coroutine_socketpair(STREAM_PF_UNIX, STREAM_SOCK_STREAM, STREAM_IPPROTO_IP);
        }
        $thread = new Thread(__FILE__, $sockets[1], $rdata);
        $reader = IS_WIN ? Swoole\Coroutine\Socket::import($sockets[0]) : $sockets[0];
        Assert::isInstanceOf($reader, Swoole\Coroutine\Socket::class);
        Assert::eq($reader->recv(8192), $rdata);
        $thread->join();
        Assert::same($thread->getExitStatus(), 0);
        echo "DONE\n";
    });
} else {
    $socket = $args[0];
    $rdata = $args[1];
    Co\run(function () use ($socket, $rdata, $argv) {
        if (IS_WIN) {
            $socket = Swoole\Coroutine\Socket::import($socket);
            Assert::isInstanceOf($socket, Swoole\Coroutine\Socket::class);
        }
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
