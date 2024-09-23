--TEST--
swoole_thread: queue notify all
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
use Swoole\Thread\Barrier;

const C = 4;

$args = Thread::getArguments();

if (empty($args)) {
    $threads = [];
    $queue = new Queue;
    $barrier = new Barrier(C + 1);
    $uuid = uniqid();
    for ($i = 0; $i < C; $i++) {
        $threads[] = new Thread(__FILE__, $i, $queue, $uuid, $barrier);
    }
    $barrier->wait();
    usleep(10000);
    $queue->push($uuid, Queue::NOTIFY_ALL);
    for ($i = 0; $i < C; $i++) {
        $threads[$i]->join();
    }
    Assert::eq($queue->count(), 0);
} else {
    $i = $args[0];
    $queue = $args[1];
    $uuid = $args[2];
    $barrier = $args[3];
    $barrier->wait();
    $job = $queue->pop(-1);
    if ($job !== null) {
        Assert::eq($job, $uuid);
    } else {
        Assert::eq(swoole_last_error(), SWOOLE_ERROR_NO_PAYLOAD);
    }
    exit(0);
}
?>
--EXPECTF--
