--TEST--
swoole_coroutine/destruct: rearm setTimeLimit inside a destructor that yields
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

use Swoole\Coroutine;
use Swoole\Coroutine\TimeoutException;
use Swoole\Timer;

class RearmInDestructor
{
    public function __destruct()
    {
        echo "destructor start\n";
        try {
            // Rearming the time limit from a destructor runs during coroutine teardown.
            // The armed timeout must still fire, otherwise the sleep below completes.
            Assert::true(Coroutine::setTimeLimit(0.05));
            Coroutine::sleep(0.3);
            echo "sleep completed without timeout\n";
        } catch (TimeoutException $e) {
            echo "destructor timed out\n";
        }
        echo "destructor end\n";
    }
}

go(function () {
    // Teardown must preserve the pending timer until the destructor replaces it.
    Assert::true(Coroutine::setTimeLimit(10));
    Coroutine::getContext()->value = new RearmInDestructor;
});

Swoole\Event::wait();

Assert::same(Timer::stats()['num'], 0);
echo "done\n";
?>
--EXPECT--
destructor start
destructor timed out
destructor end
done
