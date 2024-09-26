--TEST--
swoole_thread: Affinity
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_nts();
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Thread;

$tm = new \SwooleTest\ThreadManager();

Assert::eq(Thread::API_NAME, 'POSIX Threads');

$tm->parentFunc = function () {
    $thread = new Thread(__FILE__, 'child');
    $r = Thread::getAffinity();
    Assert::eq(count($r), swoole_cpu_num());
    Assert::assert(Thread::setAffinity([1]));
    Assert::eq(Thread::getAffinity(), [1]);
    $thread->join();
};

$tm->childFunc = function () {
    $r = Thread::getAffinity();
    Assert::eq(count($r), swoole_cpu_num());
    Assert::assert(Thread::setAffinity([0]));
    Assert::eq(Thread::getAffinity(), [0]);
};

$tm->run();
?>
--EXPECTF--
