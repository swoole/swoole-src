--TEST--
swoole_redis_coro: redis client set options
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
Co::set(['socket_timeout' => -1]);
go(function () {
    $redis = new Swoole\Coroutine\Redis();

    assert($redis->sock === 0);

    $real_connect_time = microtime(true);
    $ret = $redis->connect(REDIS_SERVER_HOST, REDIS_SERVER_PORT);
    $real_connect_time = microtime(true) - $real_connect_time;

    assert($ret);
    assert(($fd = $redis->sock) > 0);

    $fake_connect_time = 0;
    for ($n = MAX_REQUESTS; $n--;) {
        $fake_connect_time = microtime(true);
        $ret = $redis->connect(REDIS_SERVER_HOST, REDIS_SERVER_PORT);
        $fake_connect_time = microtime(true) - $fake_connect_time;
        assert($ret);
        assert($fake_connect_time < $real_connect_time);
    }

    $real_connect_time = microtime(true);
    $redis->connect(MYSQL_SERVER_HOST, MYSQL_SERVER_PORT);
    $real_connect_time = microtime(true) - $real_connect_time;
    assert($fake_connect_time < $real_connect_time);
    assert(!$redis->get('foo'));
    assert($redis->errCode === SWOOLE_REDIS_ERR_PROTOCOL);
});
swoole_event_wait();
echo "DONE\n";
?>
--EXPECT--
DONE
