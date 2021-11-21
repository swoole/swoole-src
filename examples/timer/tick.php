<?php
function timeout($tm)
{
    echo time() . ": Timeout #$tm\n";
}
$timer1 = Swoole\Timer::tick(1000, 'timeout', 1);
$timer2 = Swoole\Timer::tick(2000, 'timeout', 2);

Swoole\Timer::tick(3000, function($id) {
    timeout($id);
    //Swoole\Timer::clear($id);
    static $remove = true;
    if ($remove) {
        global $timer1;
        Swoole\Timer::clear($timer1);
        Swoole\Timer::tick(7000, 'timeout', 7);
        $remove = false;
    }
});

$timer4 = Swoole\Timer::tick(4000, 'timeout', 4);
$timer5 = Swoole\Timer::tick(5000, 'timeout', 5);
$timer6 = Swoole\Timer::tick(6000, 'timeout', 6);
