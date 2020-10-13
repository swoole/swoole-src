--TEST--
swoole_redis_coro: use unixsocket
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
go(function () {
    $redis = new Swoole\Coroutine\Redis(['timeout' => 0.5]);
    Assert::assert($redis->connect(REDIS_SERVER_HOST, REDIS_SERVER_PORT));
    for ($c = MAX_CONCURRENCY_MID; $c--;) {
        for ($n = MAX_REQUESTS; $n--;) {
            $key = md5(get_safe_random(mt_rand(1, 128)));
            $value = md5(get_safe_random(mt_rand(1, 128)));
            Assert::assert($redis->set($key, $value));
            Assert::same($redis->get($key), $value);
            Assert::assert($redis->delete($key));
        }
    }
});
swoole_event_wait();
echo "DONE\n";
?>
--EXPECT--
DONE
