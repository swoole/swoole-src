--TEST--
swoole_redis_coro: redis select db
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
go(function () {
    $redis = new Swoole\Coroutine\Redis();
    assert($redis->getDBNum() === false);

    $ret = $redis->connect(REDIS_SERVER_HOST, REDIS_SERVER_PORT);
    assert($ret);

    $ret = $redis->getDBNum();
    assert($ret === 0);

    $ret = $redis->select(1);
    assert($ret);

    $ret = $redis->getDBNum();
    assert($ret === 1);

    $ret = $redis->set('a', 1);
    assert($ret);

    $redis = new Swoole\Coroutine\Redis(['database' => 1]);

    $ret = $redis->getDBNum();
    assert($ret === false);

    $ret = $redis->connect(REDIS_SERVER_HOST, REDIS_SERVER_PORT);
    assert($ret);

    $ret = $redis->getDBNum();
    assert($ret === 1);

    $ret = $redis->get('a');
    assert($ret === 1);
});
swoole_event_wait();
echo "DONE\n";
?>
--EXPECT--
DONE
