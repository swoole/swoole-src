--TEST--
swoole_redis_coro: redis unsubscribe all
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

go(function () {
    $redis = new Co\Redis();
    $ret = $redis->connect(REDIS_SERVER_HOST, REDIS_SERVER_PORT);
    assert($ret);

    $ret = $redis->subscribe(['channel1', 'channel2']);
    assert($ret);

    for ($i = 0; $i < 2; ++$i)
    {
        $ret = $redis->recv();
        Assert::eq($ret[0], 'subscribe');
    }

    $ret = $redis->getDefer();
    assert(!$ret);

    $ret = $redis->set('a', '1');
    assert(!$ret);

    $ret = $redis->setDefer(false);
    assert(!$ret);

    $ret = $redis->unsubscribe(['channel1', 'channel2']);
    assert($ret);

    for ($i = 0; $i < 2; ++$i)
    {
        $ret = $redis->recv();
        Assert::eq($ret[0], 'unsubscribe');
        Assert::eq($ret[2], 1 - $i);
    }

    $ret = $redis->getDefer();
    assert(!$ret);

    $ret = $redis->set('a', '1');
    assert($ret);

    $ret = $redis->setDefer(false);
    assert($ret);

    $redis->close();
});

?>
--EXPECTF--
Warning: Swoole\Coroutine\Redis::setDefer(): you should not use setDefer after subscribe in %s/tests/swoole_redis_coro/unsubscribe_all.php on line 24
