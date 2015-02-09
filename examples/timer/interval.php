<?php
swoole_timer_add(3000, function($interval) {
    echo "timer[$interval] :".microtime(true)." called\n";
    swoole_timer_del(2000);
});

swoole_timer_add(1000, function($interval) {
    echo "timer[$interval] :".microtime(true)." called\n";
    swoole_timer_del(1000);
    swoole_timer_del(1000);
});

swoole_timer_add(2000, function($interval) {
    echo "timer[$interval] :".microtime(true)." called\n";
});

swoole_process::signal(SIGTERM, function() {
        swoole_event_exit();
});
