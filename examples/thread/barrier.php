<?php
// Thread\Barrier makes two threads meet at the same point. Requires a ZTS
// build with --enable-swoole-thread. Run: php examples/thread/barrier.php
use Swoole\Thread;
use Swoole\Thread\Barrier;

$args = Thread::getArguments();
if (empty($args)) {
    $barrier = new Barrier(2);
    $thread = new Thread(__FILE__, $barrier);
    $barrier->wait();
    echo 'both threads reached the barrier' . PHP_EOL;
    $thread->join();
} else {
    $args[0]->wait();
    echo 'child thread reached the barrier' . PHP_EOL;
}
