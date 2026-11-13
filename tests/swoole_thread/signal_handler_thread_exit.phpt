--TEST--
swoole_thread: child threads and their processes keep the main thread's signal handlers
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_nts();
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Event;
use Swoole\Process;
use Swoole\Thread;

$tm = new \SwooleTest\ThreadManager();

$tm->parentFunc = function () {
    swoole_async_set(['wait_signal' => true]);
    Process::signal(SIGTERM, function ($signo) {
        echo "signal $signo\n";
        Process::signal(SIGTERM, null);
    });
    $thread = new Thread(__FILE__, 'child');
    $thread->join();
    Process::kill(getmypid(), SIGTERM);
    Event::wait();
};

$tm->childFunc = function () {
    $process = new Process(function () {
        echo "process\n";
    });
    $process->start();
    $status = Process::wait();
    Assert::same($status['signal'], 0);
    Assert::same($status['code'], 0);
};

$tm->run();
?>
--EXPECT--
process
signal 15
