<?php
// Timer::tick() repeats a callback; run() provides the event loop that drives it.
// Run: php examples/timer/tick_basic.php
use function Swoole\Coroutine\run;

run(function () {
    $count = 0;
    $id = Swoole\Timer::tick(100, function () use (&$count) {
        $count++;
        echo "tick $count" . PHP_EOL;
    });
    Swoole\Coroutine\System::sleep(0.35);
    Swoole\Timer::clear($id);
    echo 'timer stopped' . PHP_EOL;
});
