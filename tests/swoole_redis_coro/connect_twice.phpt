--TEST--
swoole_redis_coro: connect twice
--SKIPIF--
<?php require __DIR__ . "/../include/skipif.inc";
if (!class_exists("Swoole\\Coroutine\\Redis", false))
{
    exit("SKIP");
}
?>
--FILE--
<?php
require_once __DIR__ . "/../include/swoole.inc";
require_once __DIR__ . "/../include/lib/curl.php";

//Co::set(['log_level' => SWOOLE_LOG_TRACE, 'trace_flags' => SWOOLE_TRACE_ALL]);

go(function () {
    $redis = new Swoole\Coroutine\Redis();
    echo "connect [1]\n";
    $redis->connect('127.0.0.1', 6379);
    assert($redis->connected === true);
    echo "close [1]\n";
    $redis->close();
    assert($redis->connected === false);
    echo "connect [2]\n";
    $redis->connect('127.0.0.1', 6379);
    assert($redis->connected === true);
    echo "close [2]\n";
    $redis->close();
    assert($redis->connected === false);
});

swoole_event::wait();
?>
--EXPECT--
connect [1]
close [1]
connect [2]
close [2]
