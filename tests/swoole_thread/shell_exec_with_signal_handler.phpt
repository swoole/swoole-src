--TEST--
swoole_thread: shell_exec works while the main thread holds a signal listener
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
    // The listener makes signal_fci_caches[] non-empty, so the child that
    // proc_open() forks below inherits callbacks owned by the main thread's heap.
    Process::signal(SIGURG, function () {});

    $thread = new Thread(__FILE__, 'child');
    Assert::true($thread->join());
    Assert::same($thread->getExitStatus(), 0);
    echo "DONE\n";
} else {
    // proc_open() forks with SW_FORK_EXEC, and the AFTER_FORK hook still runs
    // the child-only signal state reset before execv().
    Assert::same(trim((string) shell_exec('echo hello')), 'hello');

}
?>
--EXPECT--
DONE
