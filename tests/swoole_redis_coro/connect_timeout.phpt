--TEST--
swoole_redis_coro: redis client timeout
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
$GLOBALS['socket'] = new Swoole\Coroutine\Socket(AF_INET, SOCK_STREAM, 0);
$GLOBALS['socket']->bind('127.0.0.1');
go(function () {
    $timeout = mt_rand(100, 500) / 1000;
    $redis = new Swoole\Coroutine\Redis(['timeout' => $timeout]);
    $s = microtime(true);
    $ret = $redis->connect('127.0.0.1', $GLOBALS['socket']->getsockname()['port']);
    assert(!$ret);
    assert($redis->errCode === SOCKET_ETIMEDOUT);
    assert(time_approximate($timeout, microtime(true) - $s));
});
Swoole\Event::wait();
echo "DONE\n";
?>
--EXPECT--
DONE
