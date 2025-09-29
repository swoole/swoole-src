--TEST--
swoole_thread: queue
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

const C = 4;
const N = 1024;

$args = Thread::getArguments();
$total_parent = 0;
$total_child = 0;

if (empty($args)) {
    $threads = [];
    $queue = new Queue;
    $map = new Thread\Map();
    for ($i = 0; $i < C; $i++) {
        $threads[] = new Thread(__FILE__, $i, $queue, $map);
    }
    $n = N;
    while ($n--) {
        $rdata = base64_encode(random_bytes(random_int(16, 128)));
        $total_parent += strlen($rdata);
        $queue->push($rdata, Queue::NOTIFY_ONE);
        usleep(random_int(100, 1000));
    }
    $n = 4;
    while ($n--) {
        $queue->push('', Queue::NOTIFY_ONE);
    }
    for ($i = 0; $i < C; $i++) {
        $threads[$i]->join();
        $total_child += $map[$i];
    }
    Assert::eq($total_parent, $total_child);
} else {
    $i = $args[0];
    $queue = $args[1];
    $map = $args[2];
    $map[$i] = 0;
    while (1) {
        $job = $queue->pop(-1);
        if (!$job) {
            break;
        }
        $map[$i] += strlen($job);
        Assert::assert(strlen($job), 16);
    }
    exit(0);
}
?>
--EXPECTF--
