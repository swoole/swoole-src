--TEST--
swoole_runtime: hook stream redis pconnect
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc';
skip_if_class_not_exist('Redis');
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
Swoole\Runtime::enableCoroutine();
go(function () {
    $redis = new Redis;
    Assert::assert($redis->pconnect(REDIS_SERVER_HOST, REDIS_SERVER_PORT));
    $redis->get("key");
});
go(function () {
    $redis = new Redis;
    Assert::assert($redis->pconnect(REDIS_SERVER_HOST, REDIS_SERVER_PORT));
    $redis->get("key");
});
Swoole\Event::wait();
echo "DONE\n";
?>
--EXPECT--
DONE
