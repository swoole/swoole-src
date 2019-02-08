--TEST--
swoole_redis_coro: connect twice
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

go(function () {
    $redis = new Swoole\Coroutine\Redis(['timeout' => 0.5]);
    echo "connect [1]\n";
    $redis->connect('192.0.0.1', 6379);
    echo "close [1]\n";
    assert($redis->connected === false);
    assert($redis->close() === false);
});

swoole_event::wait();
?>
--EXPECT--
connect [1]
close [1]
