<?php
swoole_timer_tick(2000, function() {
	echo "tick-1 2000ms\n";
});

usleep(500000);

swoole_timer_tick(2000, function() {
        echo "tick-2 2000ms\n";
});
