--TEST--
swoole_redis_coro: redis client timeout
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

const QUEUE_KEY_1 = 'queue:swoole_test1';
const QUEUE_KEY_2 = 'queue:swoole_test2';

Co\run(function () {
    $redis = new Swoole\Coroutine\Redis(['timeout' => 0.5]);
    $redis->connect(REDIS_SERVER_HOST, REDIS_SERVER_PORT);

    $keyArray = [QUEUE_KEY_1, QUEUE_KEY_2];

    $s = microtime(true);
    $res = $redis->blpop($keyArray, 3);
    Assert::assert(!$res);
    Assert::same($redis->errCode, SOCKET_ETIMEDOUT);
    $s = microtime(true) - $s;
    time_approximate(0.5, $s); // would not retry after timeout

    $s = microtime(true);
    $res = $redis->brpoplpush(QUEUE_KEY_1, QUEUE_KEY_2, 3);
    Assert::assert(!$res);
    Assert::same($redis->errCode, SOCKET_ETIMEDOUT);
    $s = microtime(true) - $s;
    time_approximate(0.5, $s); // would not retry after timeout

    // right way: no timeout
    $redis->setOptions(['timeout' => -1]);

    $s = microtime(true);
    $res = $redis->blpop($keyArray, 1);
    Assert::same($res, null);
    Assert::same($redis->errCode, 0);
    $s = microtime(true) - $s;
    time_approximate(1, $s);

    $s = microtime(true);
    $res = $redis->brpoplpush(QUEUE_KEY_1, QUEUE_KEY_2, 1);
    Assert::same($res, null);
    Assert::same($redis->errCode, 0);
    $s = microtime(true) - $s;
    time_approximate(1, $s);
});
echo "DONE\n";
?>
--EXPECT--
DONE
