--TEST--
swoole_redis_coro: redis subscribe multi
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

go(function () {
    $redis = new Co\Redis();
    $redis->connect(REDIS_SERVER_HOST, REDIS_SERVER_PORT);

    $val = $redis->subscribe(['test1', 'test2', 'test3']);
    Assert::assert($val);

    for ($i = 0; $i < 3; ++$i)
    {
        $val = $redis->recv();
        Assert::same($val[0], 'subscribe');
    }

    for ($i = 0; $i < 3; $i++) {
        $val = $redis->recv();
        Assert::same($val[0] ?? '', 'message');
    }

    $redis->close();
});

go(function () {
    $redis = new Co\redis;
    $redis->connect(REDIS_SERVER_HOST, REDIS_SERVER_PORT);
    co::sleep(0.1);

    $ret = $redis->publish('test1', 'hello');
    Assert::assert($ret);

    $ret = $redis->publish('test2', 'hello');
    Assert::assert($ret);

    $ret = $redis->publish('test3', 'hello');
    Assert::assert($ret);
});

?>
--EXPECT--
