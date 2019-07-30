--TEST--
swoole_redis_coro: connect the same target and different
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
Co::set(['socket_timeout' => -1]);
function test(string $host, int $port = 0)
{
    $redis = new Swoole\Coroutine\Redis();
    Assert::same($redis->sock, -1);

    $real_connect_time = microtime(true);
    $ret = $redis->connect($host, $port);
    $real_connect_time = microtime(true) - $real_connect_time;

    Assert::assert($ret);
    Assert::assert(($fd = $redis->sock) > 0);

    $fake_connect_time = 0;
    for ($n = MAX_REQUESTS; $n--;) {
        $fake_connect_time = microtime(true);
        $ret = $redis->connect($host, $port);
        $fake_connect_time = microtime(true) - $fake_connect_time;
        Assert::assert($ret);
        Assert::assert($fake_connect_time < $real_connect_time);
    }

    $real_connect_time = microtime(true);
    $redis->connect(MYSQL_SERVER_HOST, MYSQL_SERVER_PORT);
    $real_connect_time = microtime(true) - $real_connect_time;
    Assert::assert($fake_connect_time < $real_connect_time);
    Assert::assert(!$redis->get('foo'));
    Assert::same($redis->errType, SWOOLE_REDIS_ERR_PROTOCOL);
}

go('test', REDIS_SERVER_HOST, REDIS_SERVER_PORT);
if (file_exists(REDIS_SERVER_PATH)) {
    go('test', 'unix:' . str_repeat('/', mt_rand(1, 3)) . REDIS_SERVER_PATH);
}

Swoole\Event::wait();
echo "DONE\n";
?>
--EXPECT--
DONE
