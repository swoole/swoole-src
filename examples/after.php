<?php
function timeout($tm)
{
    echo time() . " Timeout #$tm\n";
    if ($tm == 3)
    {
        global $timer4;
        swoole_timer_clear($timer4);
    }
}

$timer1 = swoole_timer_after(1000, 'timeout', 1);
$timer2 = swoole_timer_after(2000, 'timeout', 2);
$timer3 = swoole_timer_after(4000, 'timeout', 3);
$timer4 = swoole_timer_after(8000, 'timeout', 4);
$timer5 = swoole_timer_after(10000, 'timeout', 5);

var_dump($timer1, $timer2, $timer3, $timer4, $timer5);