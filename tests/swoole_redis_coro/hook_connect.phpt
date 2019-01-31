--TEST--
swoole_redis_coro: hook stream redis pconnect
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc';
if (!class_exists("Redis")) {
    skip("no redis extension");
}
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
Swoole\Runtime::enableCoroutine();
go(function () {
    $redis = new Redis;
    assert($redis->pconnect(REDIS_SERVER_HOST, REDIS_SERVER_PORT));
    $redis->get("key");
});
go(function () {
    $redis = new Redis;
    assert($redis->pconnect(REDIS_SERVER_HOST, REDIS_SERVER_PORT));
    $redis->get("key");
});
?>
--EXPECT--
