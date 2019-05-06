--TEST--
swoole_redis_coro: redis client connect timeout
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
go(function () {
    $timeout = mt_rand(100, 500) / 1000;
    $redis = new Swoole\Coroutine\Redis(['timeout' => $timeout]);
    $s = microtime(true);
    $ret = $redis->connect('192.0.0.1', 9000);
    Assert::assert(!$ret);
    Assert::assert($redis->errCode === SOCKET_ETIMEDOUT);
    time_approximate($timeout, microtime(true) - $s);
});
Swoole\Event::wait();
echo "DONE\n";
?>
--EXPECT--
DONE
