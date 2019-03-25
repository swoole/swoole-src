--TEST--
swoole_feature/cross_close: redis closed by server
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';
$pm = new ProcessManager();
$pm->initRandomData(1);
$pm->parentFunc = function () use ($pm) {
    go(function () use ($pm) {
        $redis = new Co\Redis;
        assert($redis->connect('127.0.0.1', $pm->getFreePort()));
        echo "GET\n";
        assert(!$redis->get($pm->getRandomData()));
        echo "CLOSED\n";
        Assert::eq($redis->errType, SWOOLE_REDIS_ERR_EOF);
        Assert::eq($redis->errCode, SOCKET_ECONNRESET);
        $pm->kill();
        echo "DONE\n";
    });
};
$pm->childFunc = function () use ($pm) {
    $server = new Co\Socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
    assert($server->bind('127.0.0.1', $pm->getFreePort()));
    assert($server->listen());
    go(function () use ($pm, $server) {
        if (assert(($conn = $server->accept()) && $conn instanceof Co\Socket)) {
            switch_process();
            $data = $conn->recv();
            $random = $pm->getRandomData();
            $random_len = strlen($random);
            Assert::eq($data, "*2\r\n$3\r\nGET\r\n\${$random_len}\r\n{$random}\r\n");
            echo "CLOSE\n";
            $conn->close();
            switch_process();
        }
        $server->close();
    });
    $pm->wakeup();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
GET
CLOSE
CLOSED
DONE
