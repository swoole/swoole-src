--TEST--
swoole_coroutine/destruct: teardown removes a time limit armed in a destructor
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

use Swoole\Coroutine;
use Swoole\Timer;

class SetLimitInDestructor
{
    public function __destruct()
    {
        // Arm a long-lived time limit and return without yielding. The coroutine is
        // already tearing down, so this timer must be removed immediately rather than
        // left pending until it expires.
        Assert::true(Coroutine::setTimeLimit(10));
        echo "destructor armed a pending time limit\n";
    }
}

Coroutine\run(function () {
    $base = Timer::stats()['num'];
    // Neither the coroutine body nor the destructor yields, so the child runs to
    // completion (including context teardown) synchronously within go().
    go(function () {
        Coroutine::getContext()->value = new SetLimitInDestructor;
    });

    // The 10s timer cannot have expired in the meantime, so a non-zero delta here means
    // coroutine teardown leaked the reentrant time limit.
    Assert::same(Timer::stats()['num'], $base);
    echo "child torn down\n";
});

Assert::same(Timer::stats()['num'], 0);
echo "done\n";
?>
--EXPECT--
destructor armed a pending time limit
child torn down
done
