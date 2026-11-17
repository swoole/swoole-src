--TEST--
swoole_thread: proc_open works in another thread while the main thread holds a signal listener
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_nts();
skip_if_class_not_exist(Swoole\Process::class);
skip_if_function_not_exist('proc_open');
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine;
use Swoole\Process;
use Swoole\Runtime;
use Swoole\Thread;

$arguments = Thread::getArguments();

if ($arguments === null) {
    // The listener puts a zend::Callable owned by the main thread's heap into
    // signal_fci_caches[], which the child that proc_open() forks below inherits.
    // SIGCHLD must stay unregistered, otherwise swoole_proc_open() refuses.
    Process::signal(SIGURG, function () {});
    Assert::same(Coroutine::stats()['signal_listener_num'], 1);
    Runtime::enableCoroutine(SWOOLE_HOOK_PROC);
    $thread = new Thread(__FILE__, 'child');
    Assert::true($thread->join());
    Assert::same($thread->getExitStatus(), 0);
    echo "DONE\n";
} else {
    Coroutine\run(function () {
        // swoole_proc_open() forks with SW_FORK_EXEC, so the AFTER_FORK hook still
        // drops the inherited signal callback pointers in that child before execvp().
        $process = proc_open([PHP_BINARY, '-n', '-r', 'exit(0);'], [
            1 => ['pipe', 'w'],
            2 => ['pipe', 'w'],
        ], $pipes);
        Assert::resource($process);
        fclose($pipes[1]);
        fclose($pipes[2]);
        Assert::same(proc_close($process), 0);
    });
}
?>
--EXPECT--
DONE
