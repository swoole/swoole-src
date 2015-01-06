<?php

function timeout($tm)
{
    echo "Timeout #$tm\n";
}

$timer1 = swoole_timer_after(1000, 'timeout');
$timer2 = swoole_timer_after(2000, 'timeout');
$timer3 = swoole_timer_after(4000, 'timeout');
$timer4 = swoole_timer_after(8000, 'timeout');
$timer5 = swoole_timer_after(10000, 'timeout');

var_dump($timer1, $timer2, $timer3, $timer4, $timer5);