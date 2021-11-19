<?php
function timeout($tm)
{
    echo time() . ": Timeout #$tm\n";
    if ($tm == 5)
    {
        Swoole\Timer::after(3000, 'timeout', 7);
    }
}

$timer1 = Swoole\Timer::after(1000, function () {
    timeout(1);
    global $timer1, $timer3;
    Swoole\Timer::clear($timer1);
    Swoole\Timer::clear($timer3);
});

$timer2 = Swoole\Timer::after(2000, 'timeout', 2);
$timer3 = Swoole\Timer::after(4000, 'timeout', 3);
$timer4 = Swoole\Timer::after(8000, 'timeout', 4);
$timer5 = Swoole\Timer::after(10000, 'timeout', 5);
$timer6 = Swoole\Timer::after(5000, 'timeout', 6);
var_dump($timer1, $timer2, $timer3, $timer4, $timer5, $timer6);

Swoole\Process::signal(SIGTERM, function() {
	Swoole\Event::exit();
});
