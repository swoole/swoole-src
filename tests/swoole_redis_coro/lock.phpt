--TEST--
swoole_redis_coro: use unixsocket
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
go(function () {
    $redis = new Co\Redis();
    $redis->connect('127.0.0.1', 6379);
    $redis->delete('lock');
    $ret = $redis->set('lock', 1, ['nx', 'ex' => 1, 'px' => 1000]); // px will be ignored
    assert($ret);
    $ret = $redis->set('lock', 1, ['nx', 'ex' => 1, 'px' => 1000]); // px will be ignored
    assert(!$ret);
    $redis->delete('lock');
    $ret = $redis->set('lock', 1, ['nx', 'px' => 100]);
    assert($ret);
    usleep(50 * 1000);
    $ret = $redis->set('lock', 1, ['nx', 'px' => 100]);
    assert(!$ret);
    usleep(50 * 1000);
    $ret = $redis->set('lock', 1, ['nx', 'px' => 100]);
    assert($ret);
});
swoole_event_wait();
echo "DONE\n";
?>
--EXPECT--
DONE
