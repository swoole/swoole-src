--TEST--
swoole_thread: active count includes a newly created thread before its PHP entry runs
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
if ($args !== null) {
    // Keep every child alive until the parent has sampled the count, regardless of startup order.
    Assert::same($args[0]->pop(-1), 'stop');
    return;
}

Assert::same(Thread::activeCount(), 1);
$release = new Queue();
$missed = 0;
for ($round = 0; $round < 64; ++$round) {
    $thread = new Thread(__FILE__, $release);
    $missed += Thread::activeCount() !== 2;
    $release->push('stop', Queue::NOTIFY_ONE);
    Assert::true($thread->join());
    Assert::same($thread->getExitStatus(), 0);
    Assert::same(Thread::activeCount(), 1);
}
Assert::same($missed, 0);
echo "DONE\n";
?>
--EXPECT--
DONE
