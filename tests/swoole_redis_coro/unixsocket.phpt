--TEST--
swoole_redis_coro: use unixsocket
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_no_redis_unix_socket();
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
go(function () {
    $redis = new Swoole\Coroutine\Redis(['timeout' => 100]);
    assert($redis->connect('unix:/' . REDIS_SERVER_PATH, 0));
    for ($c = MAX_CONCURRENCY_MID; $c--;) {
        for ($n = MAX_REQUESTS; $n--;) {
            $key = md5(openssl_random_pseudo_bytes(mt_rand(1, 128)));
            $value = md5(openssl_random_pseudo_bytes(mt_rand(1, 128)));
            assert($redis->set($key, $value));
            assert($redis->get($key) === $value);
            assert($redis->delete($key));
        }
    }
});
swoole_event_wait();
echo "DONE\n";
?>
--EXPECT--
DONE
