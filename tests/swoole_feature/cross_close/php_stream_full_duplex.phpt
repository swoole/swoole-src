--TEST--
swoole_feature/cross_close: full duplex (php stream)
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
        assert(!$errno);
        go(function () use ($pm, $cli) {
            Co::sleep(0.001);
            echo "CLOSE\n";
            assert(fclose($cli));
            // double close
            assert(!@fclose($cli));
            $pm->kill();
            echo "DONE\n";
        });
        go(function () use ($cli) {
            echo "SEND\n";
            $size = 64 * 1024 * 1024;
            assert(fwrite($cli, str_repeat('S', $size)) < $size);
            assert(!@fclose($cli));
            echo "SEND CLOSED\n";
        });
        go(function () use ($cli) {
            echo "RECV\n";
            assert(empty(fread($cli, 8192)));
            assert(!@fclose($cli));
            echo "RECV CLOSED\n";
        });
    });
};
$pm->childFunc = function () use ($pm) {
    go(function () use ($pm) {
        $server = new Co\Socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
        assert($server->bind('127.0.0.1', $pm->getFreePort()));
        assert($server->listen());
        go(function () use ($pm, $server) {
            if (assert(($conn = $server->accept()) && $conn instanceof Co\Socket)) {
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
