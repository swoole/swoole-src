--TEST--
swoole_redis_coro: redis subscribe
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc';
?>
--FILE--
<?php
require_once __DIR__ . '/../include/bootstrap.php';
require_once __DIR__ . '/../include/lib/curl.php';

use Swoole\Coroutine as co;

const N = 100;

co::create(function () {
    $redis = new co\Redis();
    $redis->connect(REDIS_SERVER_HOST, REDIS_SERVER_PORT);
    for ($i = 0; $i < N; $i++)
    {
        $val = $redis->subscribe(['test']);
        assert($val and count($val) > 1);
    }
    $redis->close();
});

co::create(function () {
    $redis = new co\redis;
    $redis->connect(REDIS_SERVER_HOST, REDIS_SERVER_PORT);
    for ($i = 0; $i < N; $i++)
    {
        $ret = $redis->publish('test', 'hello-' . $i);
        assert($ret);
    }
});

?>
--EXPECT--

