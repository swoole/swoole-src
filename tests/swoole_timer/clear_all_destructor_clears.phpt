--TEST--
swoole_timer: clearAll when the destructor of a callback clears the other timers
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

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
    $ids[] = Timer::after(1000, function () use ($object) {});
    unset($object);
}
var_dump(Timer::clearAll());
sort($called);
var_dump($called === [0, 1, 2, 3]);
var_dump(count(Timer::list()));
Swoole\Event::wait();
?>
--EXPECT--
bool(true)
bool(true)
int(0)
