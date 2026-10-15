--TEST--
swoole_coroutine: setTimeLimit(0) removes only the current coroutine's time limit
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine;
use Swoole\Coroutine\TimeoutException;
use Swoole\Timer;

Coroutine\run(function () {
    $base = Timer::stats()['num'];
    Assert::true(Coroutine::setTimeLimit(0));
    Assert::true(Coroutine::setTimeLimit(0));
    Assert::same(Timer::stats()['num'], $base);

    Assert::true(Coroutine::setTimeLimit(0.01));
    Assert::false(Coroutine::setTimeLimit(-1));
    Assert::same(Timer::stats()['num'], $base + 1);
    Assert::true(Coroutine::setTimeLimit(0));
    Assert::true(Coroutine::setTimeLimit(0));
    Assert::same(Timer::stats()['num'], $base);

    Assert::true(Coroutine::setTimeLimit(10));
    Coroutine::create(function () {
        Assert::true(Coroutine::setTimeLimit(0));
        Assert::true(Coroutine::setTimeLimit(10));
        Assert::true(Coroutine::setTimeLimit(0));
    });
    Assert::same(Timer::stats()['num'], $base + 1);
    Assert::true(Coroutine::setTimeLimit(0));
    Assert::same(Timer::stats()['num'], $base);
    Coroutine::sleep(0.03);

    // A cleared time limit can be rearmed, including after a timeout has fired.
    for ($i = 0; $i < 2; $i++) {
        Assert::true(Coroutine::setTimeLimit(0.01));
        $timedOut = false;
        try {
            Coroutine::sleep(1);
        } catch (TimeoutException $e) {
            $timedOut = true;
            Assert::true(Coroutine::setTimeLimit(0));
            Assert::true(Coroutine::setTimeLimit(0));
        }
        Assert::true($timedOut);
    }
});

Assert::same(Timer::stats()['num'], 0);
echo "DONE\n";
?>
--EXPECT--
DONE
