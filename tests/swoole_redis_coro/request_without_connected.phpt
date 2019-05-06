--TEST--
swoole_redis_coro: redis request without connected
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
go(function () {
    $redis = new Swoole\Coroutine\Redis;
    Assert::assert(!$redis->get('foo'));
    echo "DONE\n";
});
?>
--EXPECTF--
Warning: Swoole\Coroutine\Redis::get(): The host is empty in %s/tests/swoole_redis_coro/request_without_connected.php on line 5
DONE
