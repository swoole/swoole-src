--TEST--
swoole_thread: barrier
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_nts();
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Thread;
use Swoole\Thread\Barrier;

$tm = new \SwooleTest\ThreadManager();

$tm->parentFunc = function () {
    $barrier = new Barrier(2);
    $s = microtime(true);
    $thread = new Thread(__FILE__, $barrier);
    $barrier->wait();
    Assert::greaterThanEq(microtime(true) - $s, 0.2);
    echo "main thread\n";
    $thread->join();
};

$tm->childFunc = function ($barrier) {
    echo "child thread\n";
    usleep(200_000);
    $barrier->wait();
    exit(0);
};

$tm->run();
?>
--EXPECTF--
child thread
main thread
