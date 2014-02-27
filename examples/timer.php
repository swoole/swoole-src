<?php
swoole_timer_add(1000, function($interval) {
    echo "timer[$interval] call\n";
});

swoole_timer_add(2000, function($interval) {
    echo "timer[$interval] call\n";
    swoole_timer_del(2000);
});