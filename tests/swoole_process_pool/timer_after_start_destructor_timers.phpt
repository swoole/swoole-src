--TEST--
swoole_process_pool: timers added by destructors while the master timer is released work after start() returns
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Event;
use Swoole\Process\Pool;
use Swoole\Timer;

class OnDestruct
{
    public function __construct(private Closure $fn)
    {
    }

    public function __destruct()
    {
        ($this->fn)();
    }
}

$fired = [];
$pool  = new Pool(1, SWOOLE_IPC_NONE);
$pool->on('WorkerStart', function (Pool $pool) {
    $pool->shutdown();
});
$pool->on('Shutdown', function () use (&$fired) {
    $object = new OnDestruct(function () use (&$fired) {
        $inner = new OnDestruct(function () use (&$fired) {
            Timer::after(1, function () use (&$fired) {
                $fired[] = 'inner';
            });
        });
        Timer::after(1, function () use (&$fired, $inner) {
            $fired[] = 'outer';
        });
    });
    Timer::after(60000, function () use ($object) {});
    unset($object);
});
$pool->start();
Timer::after(10, function () use (&$fired) {
    $fired[] = 'after start';
});
Event::wait();
sort($fired);
Assert::same($fired, ['after start', 'inner', 'outer']);
echo "DONE\n";
?>
--EXPECT--
DONE
