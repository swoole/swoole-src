--TEST--
swoole_redis_coro: redis select db
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
go(function () {
    $redis = new Swoole\Coroutine\Redis;
    // not connected
    Assert::false($redis->getDBNum());
    Assert::assert($redis->connect(REDIS_SERVER_HOST, REDIS_SERVER_PORT));
    // connected but not selected
    Assert::same($redis->getDBNum(), 0);
    // select and success
    Assert::true($redis->select(1));
    Assert::same($redis->getDBNum(), 1);
    // select but failed
    Assert::false($redis->select(-1));
    Assert::same($redis->errCode, SOCKET_EINVAL);
    Assert::false($redis->select(1001));
    Assert::same($redis->errCode, SOCKET_EINVAL);
    Assert::same($redis->getDBNum(), 1);

    $redis = new Swoole\Coroutine\Redis(['database' => 1]);
    // connected but not selected
    Assert::false($redis->getDBNum());
    Assert::assert($redis->connect(REDIS_SERVER_HOST, REDIS_SERVER_PORT));
    // connected but not selected
    Assert::same($redis->getDBNum(), 1);
    // set database but failed
    $redis = new Swoole\Coroutine\Redis(['database' => 1001]);
    Assert::false($redis->connect(REDIS_SERVER_HOST, REDIS_SERVER_PORT));
    Assert::false($redis->getDBNum());
    Assert::same($redis->errCode, SOCKET_EINVAL);
    echo "DONE\n";
});
?>
--EXPECT--
DONE
