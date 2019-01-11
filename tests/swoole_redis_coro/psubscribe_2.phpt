--TEST--
swoole_redis_coro: redis psubscribe 2
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

go(function () {
    $redis = new Co\Redis();
    $redis->connect(REDIS_SERVER_HOST, REDIS_SERVER_PORT);

    $redis2 = new Co\redis;
    $redis2->connect(REDIS_SERVER_HOST, REDIS_SERVER_PORT);

    for ($i = 0; $i < MAX_REQUESTS; $i++) {
        $channel = 'channel' . $i;
        $val = $redis->psubscribe([$channel . '*']);
        $channel .= 'test';
        assert($val);

        go(function () use ($channel) {
            $ret = $redis->publish($channel, 'test' . $channel);
            assert($ret);
        });

        $val = $redis->recv();
        assert($val and $val[0] == 'pmessage');
    }

    $redis->close();
});

?>
--EXPECT--
