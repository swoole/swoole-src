--TEST--
swoole_feature/cross_close: client
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
        go(function () use ($pm, $cli) {
            Co::sleep(0.001);
            echo "CLOSE\n";
            $cli->close();
            $pm->kill();
            echo "DONE\n";
        });
        Assert::assert(!($ret = @$cli->recv(-1)));
        if ($ret === false) {
            Assert::same($cli->errCode, SOCKET_ECONNRESET);
        }
        echo "CLOSED\n";
        Assert::assert(!$cli->connected);
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
RECV
CLOSE
CLOSED
DONE
