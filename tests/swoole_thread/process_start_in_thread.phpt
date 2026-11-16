--TEST--
swoole_thread/process: a process can be started from another thread
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_nts();
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Process;
use Swoole\Thread;

$arguments = Thread::getArguments();

if ($arguments === null) {
    // The listener makes signal_fci_caches[] non-empty, so the child forked by the
    // thread below reaches the sw_is_main_thread() guard inside
    // php_swoole_process_signal_clean() with a foreign heap.
    Process::signal(SIGURG, function () {});

    $thread = new Thread(__FILE__, 'child');
    Assert::true($thread->join());
    Assert::same($thread->getExitStatus(), 0);
    echo "DONE\n";
} else {
    // Swoole\Process is not serializable, so it has to be created inside the thread.
    $process = new Process(function (Process $process) {
        echo "child process\n";
    });
    Assert::greaterThan($process->start(), 0);
    $process->close();
    Assert::same(Process::wait(true)['code'], 0);
    exit(0);
}
?>
--EXPECT--
child process
DONE
