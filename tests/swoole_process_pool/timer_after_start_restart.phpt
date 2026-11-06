--TEST--
swoole_process_pool: a destructor that restarts the pool while the master timer is released keeps its new timer
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Event;
use Swoole\Process\Pool;
use Swoole\Timer;

class Restart
{
    public function __construct(private Pool $pool, private Closure $onTimer)
    {
    }

    public function __destruct()
    {
        $this->pool->on('Shutdown', static function () {});
        $this->pool->start();
        Timer::after(1, $this->onTimer);
    }
}

$fired = false;
$pool  = new Pool(1, SWOOLE_IPC_NONE);
$pool->on('WorkerStart', function (Pool $pool) {
    $pool->shutdown();
});
$pool->on('Shutdown', function (Pool $pool) use (&$fired) {
    $object = new Restart($pool, function () use (&$fired) {
        $fired = true;
    });
    Timer::after(60000, function () use ($object) {});
    unset($object);
});
$pool->start();
Event::wait();
Assert::true($fired);
echo "DONE\n";
?>
--EXPECT--
DONE
