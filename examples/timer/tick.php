<?php
swoole_timer_tick(2000, function($id) {
	echo "tick-1 2000ms\n";
    var_dump($id);
});

usleep(500000);

swoole_timer_tick(2000, function($id, $params) {
    echo "tick-2 2000ms\n";
    var_dump($id, $params);
    swoole_timer_clear($id);
}, 2);
