--TEST--
swoole_coroutine/cancel: cancel DirectoryIterator during fetch
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

$directory = sys_get_temp_dir() . '/swoole_cancel_directory_iterator_fetch_' . getmypid();
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
        $iterator = new DirectoryIterator($directory);
        $cid = Coroutine::getCid();
        foreach ($iterator as $entry) {
            Event::defer(function () use ($cid) {
                Assert::true(Coroutine::cancel($cid, true));
            });
        }
        Assert::true(false, 'foreach must not complete');
    } catch (CanceledException $e) {
    }

    Assert::eq(iterator_count(new DirectoryIterator($directory)), 3);
    echo "DONE\n";
});
?>
--EXPECT--
DONE
