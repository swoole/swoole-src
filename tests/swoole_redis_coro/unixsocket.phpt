--TEST--
swoole_redis_coro: use unixsocket
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
require __DIR__ . '/../include/config.php';
skip_if_file_not_exist(REDIS_SERVER_PATH);
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
go(function () {
    $redis = new Swoole\Coroutine\Redis(['timeout' => 100]);
    Assert::assert($redis->connect('unix:/' . REDIS_SERVER_PATH, 0));
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
