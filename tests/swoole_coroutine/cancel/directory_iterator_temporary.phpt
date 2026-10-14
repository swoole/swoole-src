--TEST--
swoole_coroutine/cancel: cancel temporary DirectoryIterator during rewind
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

$directory = sys_get_temp_dir() . '/swoole_cancel_directory_iterator_temporary_' . getmypid();
if (!is_dir($directory)) {
    mkdir($directory);
}
touch($directory . '/entry');

register_shutdown_function(function () use ($directory) {
    @unlink($directory . '/entry');
    @rmdir($directory);
});

function createDirectoryIterator(string $directory): DirectoryIterator
{
    $iterator = new DirectoryIterator($directory);
    $cid = Coroutine::getCid();
    Event::defer(function () use ($cid) {
        Assert::true(Coroutine::cancel($cid, true));
    });
    return $iterator;
}

run(function () use ($directory) {
    try {
        foreach (createDirectoryIterator($directory) as $entry) {
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
