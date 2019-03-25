--TEST--
swoole_redis_coro: connect twice
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

//Co::set(['log_level' => SWOOLE_LOG_TRACE, 'trace_flags' => SWOOLE_TRACE_ALL]);

go(function () {
    $redis = new Swoole\Coroutine\Redis();
    echo "connect [1]\n";
    $redis->connect(REDIS_SERVER_HOST, REDIS_SERVER_PORT);
    Assert::true($redis->connected);
    echo "close [1]\n";
    $redis->close();
    Assert::false($redis->connected);
    echo "connect [2]\n";
    $redis->connect(REDIS_SERVER_HOST, REDIS_SERVER_PORT);
    Assert::true($redis->connected);
    echo "close [2]\n";
    $redis->close();
    Assert::false($redis->connected);
});

swoole_event::wait();
?>
--EXPECT--
connect [1]
close [1]
connect [2]
close [2]
