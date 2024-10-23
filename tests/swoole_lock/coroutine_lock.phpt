--TEST--
swoole_lock: coroutine lock
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
if (!defined('SWOOLE_COROUTINE_LOCK')) {
    skip('coroutine lock require linux kernel >= 6.7 and liburing version >= 2.6');
}
?>
--FILE--
<?php
use Swoole\Lock;
use function Swoole\Coroutine\run;
use function Swoole\Coroutine\go;
use Swoole\Coroutine\WaitGroup;

swoole_async_set([
    'iouring_workers' => 32,
    'iouring_entries' => 20000,
    'iouring_flag' => SWOOLE_IOURING_SQPOLL
]);

$lock = new Lock(SWOOLE_COROUTINE_LOCK);

run(function () use ($argv, $lock) {
    $waitGroup = new WaitGroup();
    go(function () use ($waitGroup, $lock) {
        $waitGroup->add();
	    $lock->lock();
	    $lock->lock();
        sleep(10);
	    var_dump(1);
	    $lock->unlock();
        $waitGroup->done();
    });

    go(function () use ($waitGroup, $lock) {
	    $waitGroup->add();
        sleep(3);
        $lock->lock();
	    var_dump(2);
	    $lock->unlock();
        $waitGroup->done();
    });

    go(function () use ($waitGroup, $lock) {
	$waitGroup->add();
	    sleep(1);
        $lock->lock_read();
	    var_dump(3);
	    $lock->unlock();
        $waitGroup->done();
    });

    go(function () use ($waitGroup) {
        $waitGroup->add();
	    var_dump(5);
        $waitGroup->done();
    });

    $waitGroup->wait();
});
?>
--EXPECTF--
int(5)
int(1)
int(3)
int(2)
