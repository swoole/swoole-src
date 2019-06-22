--TEST--
swoole_redis_coro: set
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

//Co::set(['log_level' => SWOOLE_LOG_TRACE, 'trace_flags' => SWOOLE_TRACE_ALL]);

go(function () {
    $redis = new Swoole\Coroutine\Redis();
    $redis->connect(REDIS_SERVER_HOST, REDIS_SERVER_PORT);
    Assert::assert($redis->set('key1', 'value'));
    Assert::assert($redis->set('key1', 'value', 10));
    Assert::assert($redis->ttl('key1') == 10);
    /**
     * xx+ex
     */
    Assert::assert($redis->set('key1', 'value', ['xx', 'ex' => 30]));
    Assert::assert($redis->ttl('key1') == 30);
    /**
     * delete
     */
    Assert::assert($redis->delete('key1'));
    /**
     * nx+ex
     */
    Assert::assert($redis->set('key1', 'value', ['nx', 'ex' => 20]));
    Assert::assert($redis->ttl('key1') == 20);

    /**
     * px
     */
    Assert::assert($redis->set('key1', 'value', ['xx', 'px' => 10000]));
    Assert::assert($redis->ttl('key1') == 10);
    echo "OK\n";
});

swoole_event::wait();
?>
--EXPECT--
OK
