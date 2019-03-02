--TEST--
swoole_redis_coro: redis subscribe 2
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

go(function () {
    $redis = new Co\Redis;
    $redis->connect(REDIS_SERVER_HOST, REDIS_SERVER_PORT);

    $redis2 = new Co\Redis;
    $redis2->connect(REDIS_SERVER_HOST, REDIS_SERVER_PORT);

    for ($i = 0; $i < MAX_REQUESTS; $i++) {
        $channel = 'channel' . $i;
        $val = $redis->subscribe([$channel]);
        assert($val);

        $val = $redis->recv();
        assert($val[0] == 'subscribe' && $val[1] == $channel);

        go(function () use ($channel, $redis2) {
            $ret = $redis2->publish($channel, 'test' . $channel);
            assert($ret);
        });

        $val = $redis->recv();
        Assert::eq($val and $val[0], 'message' and $val[1] == $channel and $val[2] == 'test' . $channel);
    }

    $redis->close();
    $redis2->close();
});

?>
--EXPECT--
