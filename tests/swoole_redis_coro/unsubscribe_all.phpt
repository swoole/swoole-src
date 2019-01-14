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
    assert($ret[0][0] == 'subscribe');
    assert($ret[0][1] == 'channel1');
    assert($ret[1][0] == 'subscribe');
    assert($ret[1][1] == 'channel2');

    $ret = $redis->getDefer();
    assert(!$ret);

    $ret = $redis->set('a', '1');
    assert(!$ret);

    $ret = $redis->setDefer(false);
    assert(!$ret);

    $ret = $redis->unsubscribe(['channel1', 'channel2']);
    assert($ret[0][0] == 'unsubscribe');
    assert($ret[0][1] == 'channel1');
    assert($ret[0][2] == 1);
    assert($ret[1][2] == 0);

    $ret = $redis->getDefer();
    assert(!$ret);

    $ret = $redis->set('a', '1');
    assert($ret);

    $ret = $redis->setDefer(false);
    assert($ret);

    $redis->close();
});

?>
--EXPECT--
