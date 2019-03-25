--TEST--
swoole_redis_coro: redis select
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
go(function () {
    $redis = new Swoole\Coroutine\Redis;
    assert($redis->connect(REDIS_SERVER_HOST, REDIS_SERVER_PORT));
    assert($redis->select(0));
    assert($redis->set('foo', $random0 = get_safe_random()));
    assert($redis->select(1));
    assert($redis->set('foo', $random1 = get_safe_random()));
    $foo = $redis->get('foo');
    assert($foo !== $random0);
    Assert::eq($foo, $random1);
    assert($redis->select(0));
    $foo = $redis->get('foo');
    Assert::eq($foo, $random0);
    assert($foo !== $random1);
    assert($redis->select(1));

    // test whether it's OK after automatic reconnected
    $redis_killer = new Swoole\Coroutine\Redis;
    $redis_killer->connect(REDIS_SERVER_HOST, REDIS_SERVER_PORT);
    $redis_killer->request(['CLIENT', 'KILL', 'TYPE', 'normal']);

    $foo = $redis->get('foo');
    assert($foo !== $random0);
    Assert::eq($foo, $random1);

    echo "DONE\n";
});
?>
--EXPECT--
DONE
