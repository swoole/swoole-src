--TEST--
swoole_thread: thread status
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_nts();
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Thread;
use Swoole\Thread\Queue;

$args = Thread::getArguments();
if ($args) {
    [$ready, $release] = $args;
    $ready->push(true, Queue::NOTIFY_ONE);
    Assert::true($release->pop(5));
    return;
}

foreach ([false, true] as $detach) {
    $ready   = new Queue();
    $release = new Queue();
    $thread  = new Thread(__FILE__, $ready, $release);
    if ($detach) {
        Assert::true($thread->detach());
    }
    // Observe a running worker and keep it alive until the status checks finish.
    Assert::true($ready->pop(5));
    Assert::same($thread->joinable(), !$detach);
    Assert::true($thread->isAlive());
    $release->push(true, Queue::NOTIFY_ONE);
    if (!$detach) {
        Assert::true($thread->join());
    } else {
        $deadline = microtime(true) + 5;
        while ($thread->isAlive() && microtime(true) < $deadline) {
            usleep(1000);
        }
    }
    Assert::false($thread->joinable());
    Assert::false($thread->isAlive());
}
?>
--EXPECT--
