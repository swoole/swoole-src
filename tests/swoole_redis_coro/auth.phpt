--TEST--
swoole_redis_coro: redis auth
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
require __DIR__ . '/../include/config.php';
$redis = new Redis;
$redis->connect(REDIS_SERVER_HOST, REDIS_SERVER_PORT);
if (!$redis->auth(REDIS_SERVER_PWD)) {
    skip('no auth');
}
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
go(function () {
    $redis = new Swoole\Coroutine\Redis;
    assert($redis->getAuth() === false);
    assert($redis->connect(REDIS_SERVER_HOST, REDIS_SERVER_PORT));
    assert($redis->getAuth() === false);
    assert(!$redis->auth(get_safe_random()));
    assert($redis->errCode === SOCKET_EINVAL);
    assert($redis->getAuth() === false);
    assert($redis->auth(REDIS_SERVER_PWD));
    assert($redis->getAuth() === REDIS_SERVER_PWD);
    // auth by connect
    $redis = new Swoole\Coroutine\Redis(['password' => REDIS_SERVER_PWD]);
    assert($redis->connect(REDIS_SERVER_HOST, REDIS_SERVER_PORT));
    assert($redis->set('foo', $random = get_safe_random()));
    assert($redis->get('foo') === $random);
    // auth failed when connect
    $redis = new Swoole\Coroutine\Redis(['password' =>  get_safe_random()]);
    assert(!$redis->connect(REDIS_SERVER_HOST, REDIS_SERVER_PORT));
    echo "DONE\n";
});
?>
--EXPECT--
DONE
