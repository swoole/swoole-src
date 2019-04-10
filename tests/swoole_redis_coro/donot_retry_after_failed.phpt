--TEST--
swoole_redis_coro: don not retry again after connect failed
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$sock = new Swoole\Coroutine\Socket(AF_INET, SOCK_STREAM, 0);
$sock->bind('127.0.0.1');
$info = $sock->getsockname();
$port = $info['port'];

$cid = go(function () use ($sock) {
    $sock->listen();
    $sock->accept();
    co::yield();
    $sock->close();
});

go(function () use ($cid, $port) {
    $redis = new Swoole\Coroutine\Redis();
    $ret = $redis->connect('127.0.0.1', 65535);
    assert(!$ret);
    Assert::eq($redis->errCode, SOCKET_ECONNREFUSED);
    for ($n = MAX_REQUESTS; $n--;) {
        $ret = $redis->get('foo');
        assert(!$ret);
        Assert::eq($redis->errType, SWOOLE_REDIS_ERR_CLOSED);
    }
    $ret = $redis->connect('127.0.0.1', $port);
    assert($ret);
    assert($redis->connected);
    Assert::eq($redis->errCode, 0, $redis->errCode);
    Assert::eq($redis->errMsg, '', $redis->errMsg);
    co::sleep(0.001);
    co::resume($cid);
});
swoole_event_wait();
echo "DONE\n";
?>
--EXPECT--
DONE
