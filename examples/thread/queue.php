<?php
// Thread\Queue passes data between threads. Requires a ZTS build with
// --enable-swoole-thread. Run: php examples/thread/queue.php
use Swoole\Thread;
use Swoole\Thread\Queue;

$args = Thread::getArguments();
if (empty($args)) {
    $queue = new Queue();
    $thread = new Thread(__FILE__, $queue);
    while ($queue->count() === 0) {
        usleep(10000);
    }
    echo 'received: ', $queue->pop(), PHP_EOL;
    $thread->join();
} else {
    $args[0]->push('hello from the child thread', Queue::NOTIFY_ONE);
}
