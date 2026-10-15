--TEST--
swoole_coroutine: rearm setTimeLimit after a timeout
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use function Swoole\Coroutine\run;
use function Swoole\Coroutine\go;
use Swoole\Coroutine;
use Swoole\Coroutine\WaitGroup;
use Swoole\Coroutine\TimeoutException;
use Swoole\Timer;

run(function () {
    $waitGroup = new WaitGroup();
    go(function() use ($waitGroup) {
        $waitGroup->add();

        try {
            Coroutine::setTimeLimit(0.1);
            Coroutine::sleep(1);
        } catch (TimeoutException $e) {
            // The timer set by setTimeLimit is not deleted until it returns from Timer::select; here it is still 1
            Assert::same(Timer::stats()['num'], 1);
            echo "first: timed out\n";
        }

        // After the timeout, set a new time limit in the same coroutine
        try {
            Coroutine::setTimeLimit(0.1);
            Coroutine::sleep(1);
        } catch (TimeoutException $e) {
            // The timer set by setTimeLimit is not deleted until it returns from Timer::select; here it is still 1
            Assert::same(Timer::stats()['num'], 1);
            echo "second: timed out\n";
        }

        Coroutine::setTimeLimit(2);
        // The timer from line 32 has not yet been popped out of select, plus the just-set setTimeLimit(2), there are two in total
        Assert::same(Timer::stats()['num'], 2);
        $waitGroup->done();
    });

    $waitGroup->wait();

    // The child coroutine has completed its task and switches directly back to the main coroutine; as long as it has not yet returned from Timer::select, the number of timers is still 2.
    Assert::same(Timer::stats()['num'], 2);
    echo "DONE\n";
});
Assert::same(Timer::stats()['num'], 0);
?>
--EXPECT--
first: timed out
second: timed out
DONE
