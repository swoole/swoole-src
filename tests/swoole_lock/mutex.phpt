--TEST--
swoole_lock: mutex
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Process;

$fp = STDOUT;

$lock = new Swoole\Lock(SWOOLE_MUTEX);
$pid = posix_getpid();
fwrite($fp, "[Master]create lock\n");
$lock->lock();

$process1 = new Process(function ($p) use ($lock, $fp) {
    fwrite($fp, "[Child 1] Wait Lock\n");
    $lock->lock();
    usleep(10);
    fwrite($fp, "[Child 1] Get Lock\n");
    $lock->unlock();
    fwrite($fp, "[Child 1] exit\n");
});
$process1->start();

$process2 = new Process(function ($p) use ($lock, $fp) {
    fwrite($fp, "[Child 2] Sleep\n");
    sleep(1);
    fwrite($fp, "[Child 2] Release Lock\n");
    $lock->unlock();
    fwrite($fp, "[Child 2] exit\n");
});
$process2->start();

Process::wait();
Process::wait();
?>
--EXPECTF--
[Master]create lock
[Child 1] Wait Lock
[Child 2] Sleep
[Child 2] Release Lock
[Child 2] exit
[Child 1] Get Lock
[Child 1] exit
