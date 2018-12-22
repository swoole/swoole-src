--TEST--
swoole_redis_coro: redis subscribe
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

go(function () {
    $redis = new Co\Redis();
    $redis->connect(REDIS_SERVER_HOST, REDIS_SERVER_PORT);
    for ($i = 0; $i < MAX_REQUESTS; $i++) {
        $val = $redis->subscribe(['test']);
        assert($val and count($val) > 1);
    }
    $redis->close();
});

go(function () {
    $redis = new Co\redis;
    $redis->connect(REDIS_SERVER_HOST, REDIS_SERVER_PORT);
    for ($i = 0; $i < MAX_REQUESTS; $i++) {
        $ret = $redis->publish('test', 'hello-' . $i);
        assert($ret);
    }
});

?>
--EXPECT--
