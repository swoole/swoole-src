--TEST--
swoole_coroutine_lock: coroutine try lock
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php

use Swoole\Coroutine\Lock;
use function Swoole\Coroutine\run;
use function Swoole\Coroutine\go;
use Swoole\Coroutine\WaitGroup;

if (defined('SWOOLE_IOURING_SQPOLL')) {
    swoole_async_set([
        'iouring_workers' => 32,
        'iouring_entries' => 20000,
        'iouring_flag' => SWOOLE_IOURING_SQPOLL
    ]);
}

$lock = new Lock(false);

run(function () use ($argv, $lock) {
    $waitGroup = new WaitGroup();
    go(function () use ($waitGroup, $lock) {
        $waitGroup->add();
        $lock->lock();
        usleep(100000);
        var_dump(1);
        $lock->unlock();
        $waitGroup->done();
    });

    go(function () use ($waitGroup, $lock) {
        $waitGroup->add();
        if (!$lock->lock(LOCK_NB)) {
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
