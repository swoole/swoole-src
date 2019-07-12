--TEST--
swoole_redis_coro: redis error return
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
go(function () {
    $redis = new \Swoole\Coroutine\Redis(['timeout' => 3]);
    $redis->connect(REDIS_SERVER_HOST, REDIS_SERVER_PORT);
    $res = $redis->set('foo', 'bar');
    Assert::assert($res && $redis->errCode === 0 && $redis->errMsg === '');
    $res = $redis->hIncrBy('foo', 'bar', 123);
    Assert::assert(!$res);
    Assert::same($redis->errType, SWOOLE_REDIS_ERR_OTHER);
    var_dump($redis->errMsg);
    $res = $redis->set('foo', 'baz');
    Assert::assert($res && $redis->errCode === 0 && $redis->errMsg === '');
});
?>
--EXPECT--
string(65) "WRONGTYPE Operation against a key holding the wrong kind of value"
