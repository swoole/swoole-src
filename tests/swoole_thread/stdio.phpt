--TEST--
swoole_thread: stdio
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
    $thread->join();
    echo "main thread\n";
};

$tm->childFunc = function ($lock) {
    echo "child thread\n";
    usleep(200_000);
    $lock->unlock();
    fwrite(STDOUT, "hello swoole\n");
    Assert::notEmpty(STDIN);
    exit(0);
};

$tm->run();
echo "DONE\n";
?>
--EXPECTF--
child thread
hello swoole
main thread
DONE
