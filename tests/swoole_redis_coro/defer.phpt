--TEST--
swoole_redis_coro: defer
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

//Co::set(['log_level' => SWOOLE_LOG_TRACE, 'trace_flags' => SWOOLE_TRACE_ALL]);

go(function () {
    $redis = new Swoole\Coroutine\Redis();
    echo "CONNECT [1]\n";
    $redis->connect(REDIS_SERVER_HOST, REDIS_SERVER_PORT);
    $redis->setDefer();
    echo "SET [1]\n";
    $redis->set('key1', 'value');

    $redis2 = new Swoole\Coroutine\Redis();
    echo "CONNECT [2]\n";
    $redis2->connect(REDIS_SERVER_HOST, REDIS_SERVER_PORT);
    $redis2->setDefer();
    echo "GET [2]\n";
    $redis2->get('key1');

    echo "RECV [1]\n";
    $result1 = $redis->recv();
    var_dump($result1);

    echo "RECV [2]\n";
    $result2 = $redis2->recv();
    var_dump($result2);
});

swoole_event::wait();
?>
--EXPECT--
CONNECT [1]
SET [1]
CONNECT [2]
GET [2]
RECV [1]
bool(true)
RECV [2]
string(5) "value"
