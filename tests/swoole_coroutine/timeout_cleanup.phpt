--TEST--
swoole_coroutine: replace and release setTimeLimit timers
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine;
use Swoole\Coroutine\TimeoutException;
use Swoole\Timer;

Coroutine\run(function () {
    $timerCount = Timer::stats()['num'];
    $counts = [];
    Coroutine::create(function () use ($timerCount, &$counts) {
        Coroutine::setTimeLimit(1);
        Coroutine::setTimeLimit(1);
        $counts[] = Timer::stats()['num'];
    });
    $counts[] = Timer::stats()['num'];
    Assert::same($counts, [$timerCount + 1, $timerCount]);

    $cid = Coroutine::create(function () {
        try {
            Coroutine::setTimeLimit(1);
            Coroutine::setTimeLimit(2);
            Coroutine::sleep(1.2);
            echo "completed\n";
        } catch (TimeoutException $e) {
            echo "timed out early\n";
        }
    });
    Assert::true(Coroutine::join([$cid]));
});

echo "DONE\n";
?>
--EXPECT--
completed
DONE
