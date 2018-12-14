--TEST--
swoole_redis_coro: redis client timeout
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
go(function () {
    $redis = new Swoole\Coroutine\Redis(['timeout' => 0.5]);
    $redis->connect(REDIS_SERVER_HOST, REDIS_SERVER_PORT);

    $s = microtime(true);
    $res = $redis->blpop(['test', 'test2'], 3);
    assert(!$res);
    assert($redis->errCode === SOCKET_ETIMEDOUT);
    $s = microtime(true) - $s;
    assert($s > 0.45 && $s < 0.55); // would not retry after timeout

    $s = microtime(true);
    $res = $redis->brpoplpush('test', 'test2', 3);
    assert(!$res);
    assert($redis->errCode === SOCKET_ETIMEDOUT);
    $s = microtime(true) - $s;
    assert($s > 0.45 && $s < 0.55); // would not retry after timeout

    // right way: no timeout
    $redis->setOptions(['timeout' => -1]);

    $s = microtime(true);
    $res = $redis->blpop(['test', 'test2'], 1);
    assert($res === null);
    assert($redis->errCode === 0);
    $s = microtime(true) - $s;
    assert($s > 0.9 && $s < 1.1);

    $s = microtime(true);
    $res = $redis->brpoplpush('test', 'test2', 1);
    assert($res === null);
    assert($redis->errCode === 0);
    $s = microtime(true) - $s;
    assert($s > 0.9 && $s < 1.1);
});
swoole_event_wait();
echo "DONE\n";
?>
--EXPECT--
DONE
