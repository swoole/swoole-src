<?php
// Timer::clear() cancels a tick timer; exists() confirms it is gone.
// Run: php examples/timer/clear_basic.php
use function Swoole\Coroutine\run;

run(function () {
    $id = Swoole\Timer::tick(100, function () {
        echo 'this should never print' . PHP_EOL;
    });
    Swoole\Timer::clear($id);
    var_dump(Swoole\Timer::exists($id));
    Swoole\Coroutine\System::sleep(0.15);
});
