--TEST--
swoole_coroutine_lock: reentrant lock is counted and only the owner can unlock
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine;
use Swoole\Coroutine\Lock;
use function Swoole\Coroutine\run;

run(function () {
    $lock = new Lock();
    Assert::true($lock->lock());
    Assert::true($lock->lock());
    Assert::true($lock->unlock());

    // still held after one unlock of a double lock
    Coroutine::create(function () use ($lock) {
        Assert::false($lock->lock(LOCK_EX | LOCK_NB));
        // not the owner
        Assert::false($lock->unlock());
        Assert::false($lock->lock(LOCK_EX | LOCK_NB));
    });

    Assert::true($lock->unlock());
    Coroutine::create(function () use ($lock) {
        Assert::true($lock->lock(LOCK_EX | LOCK_NB));
        Assert::true($lock->unlock());
    });
});
echo "DONE\n";
?>
--EXPECT--
DONE
