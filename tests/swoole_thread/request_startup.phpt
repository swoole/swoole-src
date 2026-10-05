--TEST--
swoole_thread: repeated concurrent request startup and shutdown
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_nts();
?>
--FILE--
<?php
$args = Swoole\Thread::getArguments();
if ($args !== null) {
    $args[0]->add();
    return;
}

require __DIR__ . '/../include/bootstrap.php';

$completed = new Swoole\Thread\Atomic();
for ($round = 0; $round < 4; $round++) {
    $threads = [];
    for ($i = 0; $i < 256; $i++) {
        $threads[] = new Swoole\Thread(__FILE__, $completed);
    }
    foreach ($threads as $thread) {
        Assert::true($thread->join());
    }
    Assert::eq($completed->get(), ($round + 1) * 256);
    Assert::eq(Swoole\Thread::activeCount(), 1);
}

echo "DONE\n";
?>
--EXPECT--
DONE
