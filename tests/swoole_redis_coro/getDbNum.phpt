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
    assert($redis->getDBNum() === false);
    assert($redis->connect(REDIS_SERVER_HOST, REDIS_SERVER_PORT));
    // connected but not selected
    assert($redis->getDBNum() === 0);
    // select and success
    assert($redis->select(1) === true);
    assert($redis->getDBNum() === 1);
    // select but failed
    assert($redis->select(-1) === false);
    assert($redis->errCode === SOCKET_EINVAL);
    assert($redis->select(1001) === false);
    assert($redis->errCode === SOCKET_EINVAL);
    assert($redis->getDBNum() === 1);

    $redis = new Swoole\Coroutine\Redis(['database' => 1]);
    // connected but not selected
    assert($redis->getDBNum() === false);
    assert($redis->connect(REDIS_SERVER_HOST, REDIS_SERVER_PORT));
    // connected but not selected
    assert($redis->getDBNum() === 1);
    // set database but failed
    $redis = new Swoole\Coroutine\Redis(['database' => 1001]);
    assert($redis->connect(REDIS_SERVER_HOST, REDIS_SERVER_PORT) === false);
    assert($redis->getDBNum() === false);
    assert($redis->errCode === SOCKET_EINVAL);
    echo "DONE\n";
});
?>
--EXPECT--
DONE
