--TEST--
swoole_redis_coro: don not retry again after connect failed
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
go(function () {
    $redis = new Swoole\Coroutine\Redis();
    $ret = $redis->connect(REDIS_SERVER_HOST, 65535);
    assert(!$ret);
    assert($redis->errCode === SOCKET_ECONNREFUSED);
    for ($n = MAX_REQUESTS; $n--;) {
        $ret = $redis->get('foo');
        assert(!$ret);
        assert($redis->errCode === SWOOLE_REDIS_ERR_CLOSED);
    }
});
swoole_event_wait();
echo "DONE\n";
?>
--EXPECT--
DONE
