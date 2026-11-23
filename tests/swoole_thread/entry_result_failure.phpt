--TEST--
swoole_thread: failed or exited entries provide no result and release shared arguments
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_nts();
skip_if_php_version_lower_than('8.4');
?>
--INI--
display_errors=0
log_errors=0
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

try {
    new Swoole\Thread('array_values', [static function (): void {}]);
    Assert::true(false);
} catch (Exception $error) {
    Assert::contains($error->getMessage(), "Serialization of 'Closure' is not allowed");
}
Assert::same(Swoole\Thread::activeCount(), 1);

$counter = new Swoole\Thread\Atomic();
$entries = [['array_keys', 42], ['WeakReference::create', $counter]];
if (PHP_VERSION_ID >= 80400) {
    $entries[] = ['exit', 17];
}
foreach ($entries as $entry) {
    $thread = new Swoole\Thread(...$entry);
    Assert::true($thread->join());
    Assert::assert($thread->getExitStatus() !== 0);
    Assert::null($thread->getResult());
}
Assert::same($counter->add(), 1);
$thread = new Swoole\Thread('get_debug_type', $counter);
Assert::true($thread->join());
Assert::same($thread->getExitStatus(), 0);
Assert::same($thread->getResult(), 'Swoole\\Thread\\Atomic');
echo "DONE\n";
?>
--EXPECT--
DONE
