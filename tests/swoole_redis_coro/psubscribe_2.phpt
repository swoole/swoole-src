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
        assert($val[0][0] == 'psubscribe' && $val[0][1] == $channel . '*');
        $channel .= 'test';

        go(function () use ($channel, $redis2) {
            $ret = $redis2->publish($channel, 'test' . $channel);
            assert($ret);
        });

        $val = $redis->recv();
        assert($val and $val[0] == 'pmessage');
    }

    $redis->close();
});

?>
--EXPECT--
