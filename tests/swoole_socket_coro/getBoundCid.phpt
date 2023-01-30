--TEST--
swoole_socket_coro: getBoundCid
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$pm = new ProcessManager();
$pm->parentFunc = function () use ($pm) {
    Co\run(function () use ($pm) {
        $sock = new Swoole\Coroutine\Socket(AF_INET, SOCK_STREAM, 0);
        Assert::assert($sock->connect('127.0.0.1', $pm->getFreePort()));
        set_socket_coro_buffer_size($sock, 8192);
        $write_co = $read_co = -1;
        go(function () use ($pm, $sock, &$write_co, &$read_co) {
            Co::sleep(0.001);
            echo "CLOSE\n";
            Assert::eq($sock->getBoundCid(SWOOLE_EVENT_READ), $read_co);
            Assert::eq($sock->getBoundCid(SWOOLE_EVENT_WRITE), $write_co);
            $sock->close();
            $pm->kill();
            echo "DONE\n";
        });
        $write_co = go(function () use ($sock) {
            echo "SEND\n";
            $size = 16 * 1024 * 1024;
            Assert::lessThan($sock->sendAll(str_repeat('S', $size)), $size);
            Assert::eq($sock->errCode, SOCKET_ECANCELED);
            echo "SEND CLOSED\n";
        });
        $read_co = go(function () use ($sock) {
            echo "RECV\n";
            Assert::false($sock->recv(-1));
            Assert::eq($sock->errCode, SOCKET_ECANCELED);
            echo "RECV CLOSED\n";
        });
    });
};
$pm->childFunc = function () use ($pm) {
    Co\run(function () use ($pm) {
        $server = new Co\Socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
        Assert::assert($server->bind('127.0.0.1', $pm->getFreePort()));
        Assert::assert($server->listen());
        go(function () use ($pm, $server) {
            if (Assert::assert(($conn = $server->accept()) && $conn instanceof Co\Socket)) {
                switch_process();
                co::sleep(5);
                $conn->close();
            }
            $server->close();
        });
        $pm->wakeup();
    });
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
SEND
RECV
CLOSE
SEND CLOSED
RECV CLOSED
DONE
