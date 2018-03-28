--TEST--
global_function: swoole_event_write

--FILE--
<?php
swoole_event_defer(function () {
    echo "defer [1]\n";
});
swoole_timer_after(100, function () {
    echo "timer [1]\n";
    swoole_timer_after(100, function () {
        echo "timer [2]\n";
    });
    swoole_event_defer(function () {
        echo "defer [2]\n";
    });
});
swoole_event_wait();
?>

--EXPECT--
defer [1]
timer [1]
defer [2]
timer [2]
