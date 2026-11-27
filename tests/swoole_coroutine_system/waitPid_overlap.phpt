--TEST--
swoole_coroutine_system: a duplicate waitPid cannot replace the original waiter
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_win();
skip('covers the SIGCHLD wait backend', defined('SWOOLE_IOURING_DEFAULT'));
?>
--FILE--
<?php
require __DIR__ . '/../include/Assert.php';

use Swoole\Coroutine;
use Swoole\Coroutine\Channel;
use Swoole\Coroutine\System;
use Swoole\Process;
use SwooleTest\Assert;

Assert::setThrowException(true);
$process = new Process(function (Process $process) {
    $process->read();
});
$pid = $process->start();
Coroutine\run(function () use ($process, $pid) {
    $completed = new Channel(1);
    Coroutine::create(fn () => $completed->push(System::waitPid($pid, 2)));
    try {
        Assert::false(System::waitPid($pid, 0.01));
        Assert::same(swoole_last_error(), SOCKET_EBUSY);
    } finally {
        $process->write('exit');
    }
    $status = $completed->pop(3);
    Assert::same($status['pid'], $pid);
    Assert::same($status['code'], 0);
    Assert::same($status['signal'], 0);
});
echo "DONE\n";
?>
--EXPECT--
DONE
