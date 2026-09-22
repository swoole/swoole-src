--TEST--
swoole_thread: the stdio file descriptors must not leak after the thread exits
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_nts();
skip_if_not_linux();
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Thread;

const THREAD_NUM = 8;

function count_open_fds(): int
{
    $fds = scandir('/proc/self/fd');
    Assert::assert(is_array($fds));
    return count(array_diff($fds, ['.', '..']));
}

$tm = new \SwooleTest\ThreadManager();

$tm->parentFunc = function () {
    $before = count_open_fds();

    $threads = [];
    for ($i = 0; $i < THREAD_NUM; $i++) {
        $threads[] = new Thread(__FILE__, 0);
    }
    foreach ($threads as $thread) {
        $thread->join();
    }
    // release the thread objects before counting, they may hold file descriptors
    $threads = [];
    usleep(100000);

    Assert::same(count_open_fds(), $before);
};

$tm->childFunc = function () {
    /**
     * Each thread registers the STDIN/STDOUT/STDERR streams with PHP_STREAM_FLAG_NO_CLOSE, the
     * duplicated file descriptors behind them must be closed when the thread exits, otherwise
     * they are leaked, see thread_unregister_stdio_file_handles().
     */
};

$tm->run();
?>
--EXPECT--
