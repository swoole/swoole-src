--TEST--
swoole_redis_coro: use unixsocket
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
go(function () {
    $redis = new Swoole\Coroutine\Redis(['timeout' => 0.5]);
    assert($redis->connect(REDIS_SERVER_HOST, REDIS_SERVER_PORT));
    for ($n = MAX_REQUESTS; $n--;) {
        $key = md5(openssl_random_pseudo_bytes(mt_rand(1, 128)));
        $value = md5(openssl_random_pseudo_bytes(mt_rand(1, 128)));
        assert($redis->set($key, $value));
        assert($redis->get($key) === $value);
        assert($redis->delete($key));
    }
});
?>
--EXPECT--
