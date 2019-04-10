--TEST--
swoole_redis_coro: redis reconnect
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
go(function () {
    $redis = new Swoole\Coroutine\Redis();
    $ret = $redis->connect(REDIS_SERVER_HOST, REDIS_SERVER_PORT);
    assert($ret);
    $ret = $redis->close();
    assert($ret);
    $ret = $redis->set('foo', 'bar');
    assert($ret);
    $ret = $redis->get('foo');
    Assert::eq($ret, 'bar');
});
swoole_event_wait();
echo "DONE\n";
?>
--EXPECT--
DONE
