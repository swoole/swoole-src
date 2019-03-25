--TEST--
swoole_redis_coro: redis client timeout
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
go(function () {
    $redis = new Swoole\Coroutine\Redis(['timeout' => 0.5]);
    $redis->connect(REDIS_SERVER_HOST, REDIS_SERVER_PORT);

    $s = microtime(true);
    $res = $redis->blpop(['test', 'test2'], 3);
    assert(!$res);
    Assert::eq($redis->errCode, SOCKET_ETIMEDOUT);
    $s = microtime(true) - $s;
    time_approximate(0.5, $s); // would not retry after timeout

    $s = microtime(true);
    $res = $redis->brpoplpush('test', 'test2', 3);
    assert(!$res);
    Assert::eq($redis->errCode, SOCKET_ETIMEDOUT);
    $s = microtime(true) - $s;
    time_approximate(0.5, $s); // would not retry after timeout

    // right way: no timeout
    $redis->setOptions(['timeout' => -1]);

    $s = microtime(true);
    $res = $redis->blpop(['test', 'test2'], 1);
    Assert::eq($res, null);
    Assert::eq($redis->errCode, 0);
    $s = microtime(true) - $s;
    time_approximate(1, $s);

    $s = microtime(true);
    $res = $redis->brpoplpush('test', 'test2', 1);
    Assert::eq($res, null);
    Assert::eq($redis->errCode, 0);
    $s = microtime(true) - $s;
    time_approximate(1, $s);
});
swoole_event_wait();
echo "DONE\n";
?>
--EXPECT--
DONE
