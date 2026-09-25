--TEST--
swoole_coroutine/cancel: cancel RecursiveDirectoryIterator during rewind
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

$directory = sys_get_temp_dir() . '/swoole_cancel_recursive_directory_iterator_' . getmypid();
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
        $iterator = new RecursiveDirectoryIterator($directory, FilesystemIterator::SKIP_DOTS);
        $cid = Coroutine::getCid();
        Event::defer(function () use ($cid) {
            Assert::true(Coroutine::cancel($cid, true));
        });
        foreach ($iterator as $entry) {
        }
        Assert::true(false, 'foreach must not complete');
    } catch (CanceledException $e) {
    }

    $iterator = new RecursiveDirectoryIterator($directory, FilesystemIterator::SKIP_DOTS);
    Assert::eq(iterator_count($iterator), 1);
    echo "DONE\n";
});
?>
--EXPECT--
DONE
