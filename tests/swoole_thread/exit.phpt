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
use SwooleTest\ThreadManager;

const CODE = 234;

$tm = new ThreadManager();

$tm->parentFunc = function () {
    $lock = new Lock;
    $lock->lock();
    $thread = new Thread(__FILE__, $lock);
    $lock->unlock();
    $thread->join();
    Assert::eq($thread->getExitStatus(), CODE);
    echo 'DONE' . PHP_EOL;
};

$tm->childFunc = function ($lock) {
    $lock->lock();
    usleep(100_000);
    exit(CODE);
};

$tm->run();
?>
--EXPECT--
DONE
