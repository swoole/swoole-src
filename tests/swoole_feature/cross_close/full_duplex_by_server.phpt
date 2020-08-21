--TEST--
swoole_feature/cross_close: full duplex and close by server
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';
$pm = new ProcessManager();
$pm->parentFunc = function () use ($pm) {
    go(function () use ($pm) {
        $cli = new Co\Client(SWOOLE_SOCK_TCP);
        Assert::assert($cli->connect('127.0.0.1', $pm->getFreePort()));
        Assert::assert($cli->connected);
        set_socket_coro_buffer_size($cli->exportSocket(), 65536);
        go(function () use ($cli) {
            echo "SEND\n";
            $size = 16 * 1024 * 1024;
            Assert::assert($cli->send(str_repeat('S', $size)) < $size);
            Assert::same($cli->errCode, SOCKET_EPIPE);
            echo "SEND CLOSED\n";
        });
        go(function () use ($cli) {
            echo "RECV\n";
            Assert::eq($cli->recv(-1), "");
            // Assert::same($cli->errCode, SOCKET_ECONNRESET);
            echo "RECV CLOSED\n";
        });
        $pm->wakeup();
    });
    Swoole\Event::wait();
    echo "DONE\n";
};
$pm->childFunc = function () use ($pm) {
    go(function () use ($pm) {
        $server = new Co\Socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
        Assert::assert($server->bind('127.0.0.1', $pm->getFreePort()));
        Assert::assert($server->listen());
        go(function () use ($pm, $server) {
            if (Assert::assert(($conn = $server->accept()) && $conn instanceof Co\Socket)) {
                $pm->wait();
                echo "CLOSE\n";
                $conn->close();
                switch_process();
            }
            $server->close();
        });
        $pm->wakeup();
    });
};
$pm->childFirst();
$pm->run();
?>
--EXPECTF--
SEND
RECV
CLOSE
%s CLOSED
%s CLOSED
DONE
