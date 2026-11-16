--TEST--
swoole_thread: the main thread keeps its signal listeners when another thread exits
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
    Process::signal(SIGURG, function () {});
    Assert::same(Coroutine::stats()['signal_listener_num'], 1);

    $thread = new Thread(__FILE__, 'child');
    Assert::true($thread->join());
    Assert::same($thread->getExitStatus(), 0);

    // The exiting thread runs request shutdown, whose cleanup must leave the
    // main thread's signal callback table and listener count intact.
    Assert::same(Coroutine::stats()['signal_listener_num'], 1);
    echo "DONE\n";
} else {

}
?>
--EXPECT--
DONE
