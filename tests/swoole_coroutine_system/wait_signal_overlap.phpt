--TEST--
swoole_coroutine_system: waitSignal rejects concurrent listeners for the same signal
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_win();
skip_if_class_not_exist(Swoole\Process::class);
?>
--FILE--
<?php
require __DIR__ . '/../include/Assert.php';

use Swoole\Coroutine;
use Swoole\Coroutine\Channel;
use Swoole\Coroutine\System;
use Swoole\Event;
use Swoole\Process;
use SwooleTest\Assert;

Assert::setThrowException(true);
Coroutine\run(function () {
    $result = new Channel(1);
    Coroutine::create(function () use ($result) {
        $result->push(System::waitSignal(SIGWINCH, 2));
    });

    Assert::false(@System::waitSignal(SIGWINCH, 0.02));
    Assert::same(swoole_last_error(), SOCKET_EBUSY);
    Assert::same(Coroutine::stats()['signal_listener_num'], 1);

    Event::defer(static fn () => Process::kill(getmypid(), SIGWINCH));
    Assert::same($result->pop(2), SIGWINCH);
    Assert::same(Coroutine::stats()['signal_listener_num'], 0);
});
echo "DONE\n";
?>
--EXPECT--
DONE
