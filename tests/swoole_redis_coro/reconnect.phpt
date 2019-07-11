--TEST--
swoole_redis_coro: redis reconnect
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
go(function () {
    $redis = new Swoole\Coroutine\Redis();
    $res = $redis->connect(REDIS_SERVER_HOST, REDIS_SERVER_PORT);
    Assert::assert($res);
    $redis->close();
    $res2 = $redis->connect(REDIS_SERVER_HOST, REDIS_SERVER_PORT);
    Assert::assert($res2);
});
?>
--EXPECT--
