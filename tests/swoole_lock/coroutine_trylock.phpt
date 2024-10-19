--TEST--
swoole_lock: coroutine try lock
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
        sleep(2);
	    var_dump(1);
	    $lock->unlock();
        $waitGroup->done();
    });

    go(function () use ($waitGroup, $lock) {
	    $waitGroup->add();
	    if (!$lock->trylock() || !$lock->trylock_read()) {
	        var_dump('lock failed');
	    }
        $waitGroup->done();
    });

    $waitGroup->wait();
});
?>
--EXPECTF--
string(11) "lock failed"
int(1)
