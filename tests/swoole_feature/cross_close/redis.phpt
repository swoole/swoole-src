--TEST--
swoole_feature/cross_close: redis
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';
$pm = new ProcessManager();
$pm->initRandomData(1);
$pm->parentFunc = function () use ($pm) {
    Swoole\Runtime::setHookFlags(SWOOLE_HOOK_ALL);
    $redis = new \redis;
    go(function () use ($pm, $redis) {
        $redis->connect('127.0.0.1', $pm->getFreePort());
        go(function () use ($pm, $redis) {
            echo "GET\n";
            go(function () use ($pm, $redis) {
                co::sleep(0.001);
                echo "CLOSE\n";
                Assert::assert($redis->close());
                echo "DONE\n";
                $pm->kill();
            });
            try {
                $ret = $redis->get($pm->getRandomData());
            } catch (\RedisException $e) {
                $ret = false;
                echo "CLOSED\n";
            }
            Assert::assert(!$ret);
        });
    });
};
$pm->childFunc = function () use ($pm) {
    go(function () use ($pm) {
        $server = new Co\Socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
        Assert::assert($server->bind('127.0.0.1', $pm->getFreePort()));
        Assert::assert($server->listen());
        go(function () use ($pm, $server) {
            $pm->wakeup();
            if (Assert::assert(($conn = $server->accept()) && $conn instanceof Co\Socket)) {
                switch_process();
                $data = $conn->recv();
                $random = $pm->getRandomData();
                $random_len = strlen($random);
                Assert::same($data, "*2\r\n$3\r\nGET\r\n\${$random_len}\r\n{$random}\r\n");
                switch_process();
                co::sleep(5);
                $conn->close();
            }
            $server->close();
        });
    });
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
GET
CLOSE
CLOSED
DONE
