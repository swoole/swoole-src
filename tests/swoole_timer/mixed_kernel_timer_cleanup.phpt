--TEST--
swoole_timer: shared destructor cleans PHP callbacks and preserves coroutine timers
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine;
use Swoole\Timer;

class TimerPayload
{
    public function __destruct()
    {
        echo "payload released\n";
    }
}

Swoole\Coroutine\run(function () {
    $payload = new TimerPayload();
    $id = Timer::after(60000, static function () use ($payload) {
        Assert::true(false);
    });
    unset($payload);
    Assert::true(Timer::clear($id));

    $channel = new Swoole\Coroutine\Channel(1);
    Timer::after(1, static function () use ($channel) {
        // This creates a kernel timer while the PHP timer callback is still alive.
        Coroutine::sleep(0.001);
        $channel->push(true);
    });
    Assert::true($channel->pop(1));
    echo "done\n";
});
?>
--EXPECT--
payload released
done
