--TEST--
swoole_thread: internal function entries receive transferred arguments
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_nts();
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$file = tempnam(sys_get_temp_dir(), 'swoole_thread_entry_');
try {
    foreach (['file_put_contents', 'FiLe_PuT_CoNtEnTs', '\\file_put_contents'] as $entry) {
        $thread = new Swoole\Thread($entry, $file, $entry);
        Assert::true($thread->join());
        Assert::same($thread->getExitStatus(), 0);
        Assert::same(file_get_contents($file), $entry);
    }
    $values = [3, 1, 2];
    $thread = new Swoole\Thread('sort', $values);
    Assert::true($thread->join());
    Assert::same($thread->getExitStatus(), 0);
    Assert::same($values, [3, 1, 2]);
    $thread = new Swoole\Thread(entry: 'gc_collect_cycles');
    Assert::true($thread->join());
    Assert::same($thread->getExitStatus(), 0);
    $thread = new Swoole\Thread('var_dump', 'worker', 42, ['answer' => true]);
    Assert::true($thread->join());
    Assert::same($thread->getExitStatus(), 0);
    Assert::same(Swoole\Thread::activeCount(), 1);
} finally {
    unlink($file);
}
echo "DONE\n";
?>
--EXPECT--
string(6) "worker"
int(42)
array(1) {
  ["answer"]=>
  bool(true)
}
DONE
