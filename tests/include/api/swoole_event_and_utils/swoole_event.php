<?php

// zan 未使用
//swoole_function swoole_event_add($fd, $cb) {}
//swoole_function swoole_event_set() {}
//swoole_function swoole_event_del($fd) {}
//swoole_function swoole_event_write($fd, $data) {}
//swoole_function swoole_event_wait() {}

//swoole_function swoole_event_exit() {}

require_once __DIR__ . "/../../../include/bootstrap.php";


swoole_timer_tick(1, function() {
    echo "tick\n";
    swoole_event_exit();
});
