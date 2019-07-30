--TEST--
swoole_feature/cross_close: client closed by server
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
        echo "RECV\n";
        Assert::same($cli->recv(-1), '');
        echo "CLOSED\n";
        while (($ret = @$cli->send(get_safe_random()))) {
            continue;
        }
        if ($cli->errCode) {
            Assert::same($cli->errCode, SOCKET_EPIPE);
        }
        while (($ret = @$cli->recv(-1))) {
            continue;
        }
        if ($ret === false) {
            Assert::same($cli->errCode, SOCKET_ECONNRESET);
        }
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
--EXPECT--
RECV
CLOSE
CLOSED
