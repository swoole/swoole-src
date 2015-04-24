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

$timer1 = swoole_timer_after(1000, function($id){
    echo "hello world";
    global $timer1;
    swoole_timer_clear($timer1);
}, 1);

$timer2 = swoole_timer_after(2000, 'timeout', 2);
$timer3 = swoole_timer_after(4000, 'timeout', 3);
$timer4 = swoole_timer_after(8000, 'timeout', 4);
$timer5 = swoole_timer_after(10000, 'timeout', 5);

swoole_process::signal(SIGTERM, function() {
	swoole_event_exit();
});

var_dump($timer1, $timer2, $timer3, $timer4, $timer5);
