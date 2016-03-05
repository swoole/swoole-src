<?php
function timeout($tm)
{
    echo time() . ": Timeout #$tm\n";
}
$timer1 = swoole_timer_tick(1000, 'timeout', 1);
$timer2 = swoole_timer_tick(2000, 'timeout', 2);

swoole_timer_tick(3000, function($id) {
    timeout($id);
    //swoole_timer_clear($id);
    static $remove = true;
    if ($remove) {
        global $timer1;
        swoole_timer_clear($timer1);
        swoole_timer_tick(7000, 'timeout', 7);
        $remove = false;
    }
});

$timer4 = swoole_timer_tick(4000, 'timeout', 4);
$timer5 = swoole_timer_tick(5000, 'timeout', 5);
$timer6 = swoole_timer_tick(6000, 'timeout', 6);
