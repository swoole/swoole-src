--TEST--
swoole_redis_coro: redis multi and exec
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require_once __DIR__ . '/../include/bootstrap.php';
require_once __DIR__ . '/../include/lib/curl.php';

go(function () {
    $redis = new \Swoole\Coroutine\Redis();
    $result = $redis->connect(REDIS_SERVER_HOST, REDIS_SERVER_PORT, false);
    assert($result);

    assert($redis->hmset('u:i:1', ['a' => 'hello', 'b' => 'world']));
    assert($redis->hmset('u:i:2', ['a' => 'rango', 'b' => 'swoole']));
    assert($redis->multi(SWOOLE_REDIS_MODE_PIPELINE));
    //$redis->multi(SWOOLE_REDIS_MODE_PIPELINE);
    $redis->hmget('u:i:1', array('a', 'b'));
    $redis->hmget('u:i:2', array('a', 'b'));

    $rs = $redis->exec();
    assert($rs and is_array($rs));
    assert($rs[0][0] == 'hello');
    assert($rs[0][1] == 'world');
    assert($rs[1][0] == 'rango');
    assert($rs[1][1] == 'swoole');
});
?>
--EXPECT--

