<?php
swoole_timer_add(10000, function($interval) {
    echo "timer[$interval] :".date("H:i:s")." call\n";
});

swoole_timer_add(5000, function($interval) {
    echo "timer[$interval] :".date("H:i:s")." call\n";
});
