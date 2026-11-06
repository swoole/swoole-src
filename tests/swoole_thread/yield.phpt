--TEST--
swoole_thread: yield while another thread is running
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
    Assert::null(Thread::yield());
    $ready->push(true, Queue::NOTIFY_ONE);
    Assert::true($release->pop(5));
    return;
}

$ready = new Queue();
$release = new Queue();
$thread = new Thread(__FILE__, $ready, $release);
Assert::true($thread->detach());
Assert::true($ready->pop(5));
Assert::null(Thread::yield());
Assert::true($thread->isAlive());
$release->push(true, Queue::NOTIFY_ONE);

$deadline = microtime(true) + 5;
while (Thread::activeCount() > 1 && microtime(true) < $deadline) {
    usleep(1000);
}
Assert::same(Thread::activeCount(), 1);
Assert::false($thread->isAlive());
?>
--EXPECT--
