<?php
// Timer::after() runs a callback once, after a delay.
// Run: php examples/timer/after_basic.php
use function Swoole\Coroutine\run;

run(function () {
    Swoole\Timer::after(100, function () {
        echo '100 ms later' . PHP_EOL;
    });
    Swoole\Coroutine\System::sleep(0.2);
    echo 'done' . PHP_EOL;
});
