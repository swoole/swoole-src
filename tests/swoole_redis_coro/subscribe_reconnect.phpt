--TEST--
swoole_redis_coro: redis subscribe reconnect
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

go(function () {
    $redis = new Co\Redis();
    $ret = $redis->connect(REDIS_SERVER_HOST, REDIS_SERVER_PORT);
    Assert::assert($ret);

    $ret = $redis->subscribe(['channel1']);
    Assert::assert($ret);

    $ret = $redis->recv();
    Assert::same($ret[0], 'subscribe');
    Assert::same($ret[1], 'channel1');

    $ret = $redis->set('a', '1');
    Assert::assert(!$ret);
    $redis->close();

    $ret = $redis->connect(REDIS_SERVER_HOST, REDIS_SERVER_PORT);
    Assert::assert($ret);

    $ret = $redis->set('a', '1');
    Assert::assert($ret);

    $redis->close();
});

?>
--EXPECT--
