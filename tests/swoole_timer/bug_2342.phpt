--TEST--
swoole_timer: bug Github#2342
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

class workerInfo
{
    public $data;
    public function __construct() {
        $this->data = str_repeat('A', 1024 * 1024 * 1);
    }
}

function worker($timerId, $info)
{
    Swoole\Timer::clear($timerId);
}
function manager($timerID)
{
    Swoole\Timer::tick( 10, 'worker', new workerInfo());
}
$mem = memory_get_usage();
$timerId = Swoole\Timer::tick(50, 'manager');
Swoole\Timer::after(500, function()use($timerId){
    Swoole\Timer::clear($timerId);
});
Swoole\Event::wait();
Assert::assert($mem + 1024 * 1024 * 1 > memory_get_usage());
echo "DONE\n";

?>
--EXPECT--
DONE
