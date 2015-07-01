<?php
function timeout($tm)
{
    echo time() . ": Timeout #$tm\n";
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

swoole_process::signal(SIGTERM, function() {
	swoole_event_exit();
});
