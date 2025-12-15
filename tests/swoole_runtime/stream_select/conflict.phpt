--TEST--
swoole_runtime/stream_select: conflict
--SKIPIF--
<?php
require __DIR__ . '/../../include/skipif.inc';
skip_if_not_linux();
?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

use Swoole\Atomic;
use Swoole\Runtime;
use Swoole\Event;

Runtime::enableCoroutine();

// Co::set(['print_backtrace_on_error' => true]);

$n = new Atomic(1);

go(function () use ($n) {
    $server = stream_socket_server('tcp://0.0.0.0:8000', $errno, $errstr, STREAM_SERVER_BIND | STREAM_SERVER_LISTEN);
    while ($n->get()) {
        $conn = @stream_socket_accept($server, 0.1);
        if ($conn) {
            go(function () use ($conn) {
                Assert::eq(fread($conn, 8192), '');
                fclose($conn);
                echo "Server done\n";
            });
            break;
        }
    }
});

go(function () use ($n) {
    $fp1 = stream_socket_client('tcp://127.0.0.1:8000', $errno, $errstr, 30);
    go(function () use ($fp1) {
        Co::sleep(0.01);
        $read = null;
        $write = [$fp1];
        $except = null;
        $rs = stream_select($read, $write, $except, 5);
        Assert::eq($rs, 0);
        stream_socket_shutdown($fp1, STREAM_SHUT_RDWR);
        echo "shutdown\n";
    });
    $rs = fread($fp1, 8192);
    Assert::eq($rs, '');
    echo "Client done\n";
});

Event::wait();
?>
--EXPECTF--
[%s]	WARNING	ReactorEpoll::add(): [Reactor#0] epoll_ctl(epfd=%d, EPOLL_CTL_ADD, fd=%d, fd_type=%d, events=1024) failed, Error: File exists[17]
shutdown
Server done
Client done
