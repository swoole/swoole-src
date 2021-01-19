--TEST--
swoole_redis_coro/compatibility_mode: hExists
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

const KEY = 'hkey';

Co\run(function() {
    $redis = new Swoole\Coroutine\Redis();
    $redis->setOptions(['compatibility_mode' => true]);
    $redis->connect(REDIS_SERVER_HOST, REDIS_SERVER_PORT);

    $redis->delete(KEY);
    $redis->hSet(KEY, 'field', 'val1');

    Assert::true($redis->hExists(KEY, 'field') === true);
    Assert::true($redis->hExists(KEY, 'field_not_found') === false);
});
?>
--EXPECT--
