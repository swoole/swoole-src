--TEST--
swoole_redis_coro: redis multi and exec
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

go(function () {
    $redis = new \Swoole\Coroutine\Redis();
    $result = $redis->connect(REDIS_SERVER_HOST, REDIS_SERVER_PORT, false);
    assert($result);

    assert($redis->hmset('u:i:1', ['a' => 'hello', 'b' => 'world']));
    assert($redis->hmset('u:i:2', ['a' => 'rango', 'b' => 'swoole']));
    assert($redis->multi());
    $redis->hmget('u:i:1', array('a', 'b'));
    $redis->hmget('u:i:2', array('a', 'b'));

    $rs = $redis->exec();
    assert($rs and is_array($rs));
    Assert::eq($rs[0][0], 'hello');
    Assert::eq($rs[0][1], 'world');
    Assert::eq($rs[1][0], 'rango');
    Assert::eq($rs[1][1], 'swoole');
    echo "DONE\n";
});
?>
--EXPECT--
DONE
