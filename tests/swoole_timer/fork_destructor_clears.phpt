--TEST--
swoole_timer: fork when the destructor of an inherited callback clears the other timers
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_class_not_exist(Swoole\Process::class);
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Process;
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

$ids = [];
$called = [];
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

$process = new Process(function () use (&$called) {
    sort($called);
    var_dump($called === [0, 1, 2, 3]);
    var_dump(count(Timer::list()));
});
$process->start();
$status = Process::wait();
Assert::same($status['code'], 0);
Assert::same($status['signal'], 0);
var_dump(Timer::clearAll());
?>
--EXPECT--
bool(true)
int(0)
bool(true)
