--TEST--
swoole_redis_coro: redis unsubscribe not all
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

go(function () {
    $redis = new Co\Redis();
    $ret = $redis->connect(REDIS_SERVER_HOST, REDIS_SERVER_PORT);
    Assert::assert($ret);

    $ret = $redis->subscribe(['channel1', 'channel2']);
    Assert::assert($ret);

    for ($i = 0; $i < 2; ++$i)
    {
        $ret = $redis->recv();
        Assert::same($ret[0], 'subscribe');
    }

    $ret = $redis->getDefer();
    Assert::assert(!$ret);

    $ret = $redis->set('a', '1');
    Assert::assert(!$ret);

    $ret = $redis->setDefer(false);
    Assert::assert(!$ret);

    $ret = $redis->unsubscribe(['channel1']);
    Assert::assert($ret);

    $ret = $redis->recv();
    Assert::same($ret[0], 'unsubscribe');
    Assert::same($ret[1], 'channel1');
    Assert::same($ret[2], 1);

    $ret = $redis->getDefer();
    Assert::assert(!$ret);

    $ret = $redis->set('a', '1');
    Assert::assert(!$ret);

    $ret = $redis->setDefer(false);
    Assert::assert(!$ret);

    $redis->close();
});

?>
--EXPECTF--
Warning: Swoole\Coroutine\Redis::setDefer(): you should not use setDefer after subscribe in %s/tests/swoole_redis_coro/unsubscribe_not_all.php on line 24

Warning: Swoole\Coroutine\Redis::setDefer(): you should not use setDefer after subscribe in %s/tests/swoole_redis_coro/unsubscribe_not_all.php on line 41
