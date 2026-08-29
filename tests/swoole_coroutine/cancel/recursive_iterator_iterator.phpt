--TEST--
swoole_coroutine/cancel: cancel RecursiveIteratorIterator during rewind
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

use function Swoole\Coroutine\run;
use Swoole\Coroutine;
use Swoole\Coroutine\CanceledException;
use Swoole\Event;
use Swoole\Runtime;

Runtime::enableCoroutine(SWOOLE_HOOK_FILE);

$directory = sys_get_temp_dir() . '/swoole_cancel_recursive_iterator_iterator_' . getmypid();
if (!is_dir($directory)) {
    mkdir($directory);
}
touch($directory . '/entry');

register_shutdown_function(function () use ($directory) {
    @unlink($directory . '/entry');
    @rmdir($directory);
});

run(function () use ($directory) {
    try {
        $inner = new RecursiveDirectoryIterator($directory, FilesystemIterator::SKIP_DOTS);
        $iterator = new RecursiveIteratorIterator($inner, RecursiveIteratorIterator::SELF_FIRST);
        $cid = Coroutine::getCid();
        Event::defer(function () use ($cid) {
            Assert::true(Coroutine::cancel($cid, true));
        });
        foreach ($iterator as $entry) {
        }
        Assert::true(false, 'foreach must not complete');
    } catch (CanceledException $e) {
    }

    $inner = new RecursiveDirectoryIterator($directory, FilesystemIterator::SKIP_DOTS);
    $iterator = new RecursiveIteratorIterator($inner, RecursiveIteratorIterator::SELF_FIRST);
    Assert::eq(iterator_count($iterator), 1);
    echo "DONE\n";
});
?>
--EXPECT--
DONE
