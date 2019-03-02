--TEST--
swoole_redis_coro: redis punsubscribe
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

go(function () {
    $redis = new Co\Redis();
    $ret = $redis->connect(REDIS_SERVER_HOST, REDIS_SERVER_PORT);
    assert($ret);

    $ret = $redis->psubscribe(['channel1']);
    assert($ret);

    $ret = $redis->recv();
    Assert::eq($ret[0], 'psubscribe');
    Assert::eq($ret[1], 'channel1');

    $ret = $redis->getDefer();
    assert(!$ret);

    $ret = $redis->set('a', '1');
    assert(!$ret);

    $ret = $redis->setDefer(false);
    assert(!$ret);

    $ret = $redis->punsubscribe(['channel1']);
    assert($ret);

    $ret = $redis->recv();
    Assert::eq($ret[0], 'punsubscribe');
    Assert::eq($ret[1], 'channel1');

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
Warning: Swoole\Coroutine\Redis::setDefer(): you should not use setDefer after subscribe in %s/tests/swoole_redis_coro/punsubscribe.php on line 22
