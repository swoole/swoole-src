<?php
function timeout($tm)
{
    echo time() . ": Timeout #$tm\n";
    if ($tm == 5)
    {
        swoole_timer_after(3000, 'timeout', 7);
    }
}

$timer1 = swoole_timer_after(1000, function () {
    timeout(1);
    global $timer1, $timer3;
    swoole_timer_clear($timer1);
    swoole_timer_clear($timer3);
});

$timer2 = swoole_timer_after(2000, 'timeout', 2);
$timer3 = swoole_timer_after(4000, 'timeout', 3);
$timer4 = swoole_timer_after(8000, 'timeout', 4);
$timer5 = swoole_timer_after(10000, 'timeout', 5);
$timer6 = swoole_timer_after(5000, 'timeout', 6);
var_dump($timer1, $timer2, $timer3, $timer4, $timer5, $timer6);

swoole_process::signal(SIGTERM, function() {
	swoole_event_exit();
});
