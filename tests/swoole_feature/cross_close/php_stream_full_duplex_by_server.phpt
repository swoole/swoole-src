--TEST--
swoole_feature/cross_close: full duplex and close by server (php stream)
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';
Swoole\Runtime::enableCoroutine();
$pm = new ProcessManager();
$pm->parentFunc = function () use ($pm) {
    go(function () use ($pm) {
        $cli = stream_socket_client("tcp://127.0.0.1:{$pm->getFreePort()}", $errno, $errstr, 1);
        Assert::true(!$errno);
        go(function () use ($cli) {
            echo "SEND\n";
            $size = 64 * 1024 * 1024;
            Assert::true(@fwrite($cli, str_repeat('S', $size)) < $size);
            echo "SEND CLOSED\n";
        });
        go(function () use ($cli) {
            echo "RECV\n";
            Assert::true(!fread($cli, 8192));
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
        Assert::true($server->bind('127.0.0.1', $pm->getFreePort()));
        Assert::true($server->listen());
        go(function () use ($pm, $server) {
            if (Assert::true(($conn = $server->accept()) && $conn instanceof Co\Socket)) {
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
