--TEST--
swoole_feature/cross_close: full duplex
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
        set_socket_coro_buffer_size($cli->exportSocket(), 8192);
        go(function () use ($pm, $cli) {
            Co::sleep(0.001);
            echo "CLOSE\n";
            $cli->close();
            $pm->kill();
            echo "DONE\n";
        });
        go(function () use ($cli) {
            echo "SEND\n";
            $size = 16 * 1024 * 1024;
            Assert::assert($cli->send(str_repeat('S', $size)) < $size);
            Assert::assert(!$cli->connected);
            echo "SEND CLOSED\n";
        });
        go(function () use ($cli) {
            echo "RECV\n";
            Assert::assert(!$cli->recv(-1));
            Assert::assert(!$cli->connected);
            echo "RECV CLOSED\n";
        });
    });
};
$pm->childFunc = function () use ($pm) {
    go(function () use ($pm) {
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
