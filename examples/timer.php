<?php
swoole_timer_add(1000, function($interval) {
    echo "timer[$interval] :".microtime(true)." called\n";
});

echo "Added timer1: ".microtime(true)."\n";

swoole_timer_add(3000, function($interval) {
    echo "timer[$interval] :".microtime(true)." called\n";
    swoole_timer_after(1000, function(){
	echo microtime(true)." Timeout, clear interval\n";
        swoole_timer_del(3000);
    });
});

echo "Added timer2: ".microtime(true)."\n";

