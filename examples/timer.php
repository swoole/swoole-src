<?php
swoole_timer_add(3000, function($interval) {
    echo "timer[$interval] :".date("H:i:s")." call\n";
});

swoole_timer_add(2000, function($interval) {
    echo "timer[$interval] :".date("H:i:s")." call\n";
});
