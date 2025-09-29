--TEST--
swoole_thread: priority
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_nts();
skip_if_not_root();
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Thread;

$tm = new \SwooleTest\ThreadManager();

Assert::eq(Thread::API_NAME, 'POSIX Threads');

function test_thread_priority($priority, $policy)
{
    $r = Thread::getPriority();
    Assert::eq($r['policy'], 0);
    Assert::eq($r['priority'], 0);
    Assert::assert(Thread::setPriority($priority, $policy));

    $r = Thread::getPriority();
    Assert::eq($r['policy'], $policy);
    Assert::eq($r['priority'], $priority);
}

$tm->parentFunc = function () {
    $thread = new Thread(__FILE__, 'child');
    test_thread_priority(10, Thread::SCHED_FIFO);
    $thread->join();
};

$tm->childFunc = function () {
    test_thread_priority(5, Thread::SCHED_RR);
};

$tm->run();
?>
--EXPECTF--
