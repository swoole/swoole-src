--TEST--
swoole_lock: lock read
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
use Swoole\Process;
use Swoole\Lock;

$lock = new Lock(Lock::RWLOCK);
$begin = microtime(true);
$process1 = new Process(function ($p) use ($lock) {
    $lock->lock(LOCK_SH);
    usleep(200_000);
    $lock->unlock();
});
$process1->start();

$process2 = new Process(function ($p) use ($lock) {
    $lock->lock(LOCK_SH);
    usleep(200_000);
    $lock->unlock();
});
$process2->start();

Process::wait();
Process::wait();

// Using shared locks, two processes will get locks at the same time and execute them concurrently
// Starting a process on Darwin costs far more than on Linux (~80ms vs ~15ms), use a larger bound there
Assert::lessThan(microtime(true) - $begin, IS_MAC_OS ? 0.5 : 0.35);
?>
--EXPECT--
