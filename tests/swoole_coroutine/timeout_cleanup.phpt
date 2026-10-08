--TEST--
swoole_coroutine: release setTimeLimit timers when the coroutine ends
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine;
use Swoole\Timer;

Coroutine\run(function () {
    $timerCount = Timer::stats()['num'];
    Coroutine::create(function () use ($timerCount) {
        Coroutine::setTimeLimit(1);
        Coroutine::setTimeLimit(1);
        Assert::same(Timer::stats()['num'], $timerCount + 2);
    });

    Assert::same(Timer::stats()['num'], $timerCount);
});

echo "DONE\n";
?>
--EXPECT--
DONE
