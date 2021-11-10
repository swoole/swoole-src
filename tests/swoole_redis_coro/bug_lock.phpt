--TEST--
swoole_redis_coro: redis client
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use SwooleTest\Redis\Lock;
use SwooleTest\Redis\SQLPool;

go(function () {
    $redis_lock = Lock::i();
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
