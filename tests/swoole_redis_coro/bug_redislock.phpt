--TEST--
swoole_redis_coro: redis client
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
require __DIR__ . '/../include/api/swoole_redis_coro/RedisLock.php';

use RedisLockBug\RedisLock;
use RedisLockBug\SQLPool;

SQLPool::init();

go(function () {
    $redis_lock = RedisLock::i();
    for ($i = 3; $i--;) {
        echo "LOCK\n";
        if (!$redis_lock->lock('SWOOLE_TEST_LOCK')) {
            echo "ERROR\n";
            $redis_lock->unlock('SWOOLE_TEST_LOCK');
        } else {
            echo "FREE\n";
        }
    }
    SQLPool::release();
});

swoole_event_wait();
?>
--EXPECT--
LOCK
FREE
LOCK
ERROR
LOCK
FREE
