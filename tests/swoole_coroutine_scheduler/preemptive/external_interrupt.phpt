--TEST--
swoole_coroutine_scheduler/preemptive: external interrupt with preemption disabled
--SKIPIF--
<?php
require __DIR__ . '/../../include/skipif.inc';
skip_if_not_linux();
?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

use Swoole\Coroutine;
use Swoole\Event;
use Swoole\Process;

use function Swoole\Coroutine\run;

Coroutine::set([
    'enable_preemptive_scheduler' => true,
    'hook_flags' => 0,
]);

run(function () {
    $coroutine = Coroutine::create(function () {
        Coroutine::yield();
    });
    Coroutine::resume($coroutine);
});

Coroutine::set(['enable_preemptive_scheduler' => false]);

$signalCount = 0;
$deferred = false;

pcntl_async_signals(true);
pcntl_signal(SIGUSR1, function () use (&$signalCount) {
    $signalCount++;
});

run(function () use (&$signalCount, &$deferred) {
    usleep(20000);

    Event::defer(function () use (&$deferred) {
        $deferred = true;
    });

    Process::kill(getmypid(), SIGUSR1);

    Assert::same($signalCount, 1);
    Assert::false($deferred);

    Coroutine::sleep(0.001);
    Assert::true($deferred);
});

echo "DONE\n";
?>
--EXPECT--
DONE
