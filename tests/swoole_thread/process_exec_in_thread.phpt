--TEST--
swoole_thread/process: a process started from another thread can exec
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
    Process::signal(SIGURG, function () {});

    $thread = new Thread(__FILE__, 'child');
    Assert::true($thread->join());
    Assert::same($thread->getExitStatus(), 0);
    echo "DONE\n";
} else {
    // Whether the child keeps running PHP or replaces its image is only decided
    // after swoole_fork() has returned, which is why start() cannot refuse here.
    $process = new Process(function (Process $process) {
        $process->exec('/bin/sh', ['-c', 'echo executed']);
    });
    Assert::greaterThan($process->start(), 0);
    $process->close();
    Assert::same(Process::wait(true)['code'], 0);
    exit(0);
}
?>
--EXPECT--
executed
DONE
