--TEST--
swoole_thread/process: Process::signal() is refused in another thread
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_nts();
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine;
use Swoole\Process;
use Swoole\Thread;

$arguments = Thread::getArguments();

if ($arguments === null) {
    Assert::same(Coroutine::stats()['signal_listener_num'], 0);

    $thread = new Thread(__FILE__, 'child');
    Assert::true($thread->join());
    Assert::same($thread->getExitStatus(), 0);

    // signal_fci_caches[] is shared by every thread, so it can only ever hold
    // callables allocated on the main thread's heap. That is what makes
    // sw_is_main_thread() the right predicate in php_swoole_process_signal_clean().
    Assert::same(Coroutine::stats()['signal_listener_num'], 0);
    echo "DONE\n";
} else {
    // SW_MUST_BE_MAIN_THREAD() returns true rather than throwing, so the refusal is
    // only observable through swoole_last_error() and the untouched listener count.
    Assert::true(Process::signal(SIGURG, function () {}));
    Assert::same(swoole_last_error(), SWOOLE_ERROR_OPERATION_NOT_SUPPORT);
    Assert::same(Coroutine::stats()['signal_listener_num'], 0);
}
?>
--EXPECT--
DONE
