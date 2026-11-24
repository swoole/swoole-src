--TEST--
swoole_thread: internal entry exceptions fail the worker and allow later threads
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_nts();
?>
--INI--
display_errors=0
log_errors=0
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

foreach ([['array_keys', 42], ['DateTimeImmutable::createFromFormat', '!Y-m-d', "bad\0date"]] as $entry) {
    $thread = new Swoole\Thread(...$entry);
    Assert::true($thread->join());
    Assert::assert($thread->getExitStatus() !== 0);
    Assert::same(Swoole\Thread::activeCount(), 1);
}
if (PHP_VERSION_ID >= 80400) {
    $thread = new Swoole\Thread('exit', 17);
    Assert::true($thread->join());
    Assert::same($thread->getExitStatus(), 17);
}
$thread = new Swoole\Thread('gc_collect_cycles');
Assert::true($thread->join());
Assert::same($thread->getExitStatus(), 0);
echo "DONE\n";
?>
--EXPECT--
DONE
