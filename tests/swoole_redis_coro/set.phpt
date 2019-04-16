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
    assert($redis->set('key1', 'value'));
    assert($redis->set('key1', 'value', 10));
    assert($redis->ttl('key1') == 10);
    /**
     * xx+ex
     */
    assert($redis->set('key1', 'value', ['xx', 'ex' => 30]));
    assert($redis->ttl('key1') == 30);
    /**
     * delete
     */
    assert($redis->delete('key1'));
    /**
     * nx+ex
     */
    assert($redis->set('key1', 'value', ['nx', 'ex' => 20]));
    assert($redis->ttl('key1') == 20);

    /**
     * px
     */
    assert($redis->set('key1', 'value', ['xx', 'px' => 10000]));
    assert($redis->ttl('key1') == 10);
});

swoole_event::wait();
?>
--EXPECT--

