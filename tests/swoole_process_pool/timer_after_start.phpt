--TEST--
swoole_process_pool: timers work after start() returns
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

// pending master timers are released, including ones whose destructors clear the others
$ids    = [];
$called = [];
$pool   = new Pool(1, SWOOLE_IPC_NONE);
$pool->on('WorkerStart', function (Pool $pool) {
    $pool->shutdown();
});
$pool->on('Shutdown', function () use (&$ids, &$called) {
    for ($i = 0; $i < 4; $i++) {
        $object = new OnDestruct(function () use (&$ids, &$called, $i) {
            foreach ($ids as $id) {
                Timer::clear($id);
            }
            $called[] = $i;
        });
        $ids[] = Timer::tick(60000, function () use ($object) {});
        unset($object);
    }
});
$pool->start();
sort($called);
Assert::same($called, [0, 1, 2, 3]);
Assert::same(Timer::stats()['num'], 0);
$fired = false;
Timer::after(100, function () use (&$fired) {
    $fired = true;
});
Event::wait();
Assert::true($fired);
echo "DONE\n";
?>
--EXPECT--
DONE
