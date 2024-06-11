--TEST--
swoole_thread: lock
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_nts();
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Thread;
use Swoole\Thread\Lock;

$tm = new \SwooleTest\ThreadManager();

$tm->parentFunc = function () {
    $lock = new Lock;
    $lock->lock();
    $thread = new Thread(__FILE__, $lock);
    $lock->lock();
    echo "main thread\n";
    $thread->join();
};

$tm->childFunc = function ($lock) {
    echo "child thread\n";
    usleep(200_000);
    $lock->unlock();
    exit(0);
};

$tm->run();
?>
--EXPECTF--
child thread
main thread
