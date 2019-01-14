--TEST--
swoole_redis_coro: redis psubscribe
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

go(function () {
    $redis = new Co\Redis();
    $redis->connect(REDIS_SERVER_HOST, REDIS_SERVER_PORT);
    $val = $redis->psubscribe(['test.*']);
    assert($val[0][0] == 'psubscribe' && $val[0][1] == 'test.*');

    for ($i = 0; $i < MAX_CONCURRENCY; $i++) {
        $val = $redis->recv();
        assert($val and $val[0] == 'pmessage');
    }

    $redis->close();
});

go(function () {
    $redis = new Co\redis;
    $redis->connect(REDIS_SERVER_HOST, REDIS_SERVER_PORT);
    co::sleep(0.1);

    for ($i = 0; $i < MAX_CONCURRENCY; $i++) {
        $ret = $redis->publish('test.a', 'hello-' . $i);
        assert($ret);
    }
});

?>
--EXPECT--
