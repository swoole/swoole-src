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
    Swoole\Runtime::setHookFlags(SWOOLE_HOOK_ALL);
    go(function () use ($pm) {
        $redis = new \redis;
        Assert::assert($redis->connect('127.0.0.1', $pm->getFreePort()));
        echo "GET\n";
        try {
            $redis->get($pm->getRandomData());
        } catch (\RedisException $e) {
            echo "CLOSED\n";
        }
        $pm->kill();
        echo "DONE\n";
    });
};
$pm->childFunc = function () use ($pm) {
    $server = new Co\Socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
    Assert::assert($server->bind('127.0.0.1', $pm->getFreePort()));
    Assert::assert($server->listen());
    go(function () use ($pm, $server) {
        if (Assert::assert(($conn = $server->accept()) && $conn instanceof Co\Socket)) {
            switch_process();
            $data = $conn->recv();
            $random = $pm->getRandomData();
            $random_len = strlen($random);
            Assert::same($data, "*2\r\n$3\r\nGET\r\n\${$random_len}\r\n{$random}\r\n");
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
