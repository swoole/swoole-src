<?php

require_once __DIR__ . "/../../../include/bootstrap.php";

//swoole_function swoole_timer_after($ms, $callback, $param = null) {}
//swoole_function swoole_timer_tick($ms, $callback) {}
//swoole_function swoole_timer_clear($timer_id) {}


function after()
{
    $start = microtime(true);
    swoole_timer_after(1000, function() use($start) {
        echo microtime(true) - $start, "\n";
        after();
    });
}

//for ($i = 0; $i < 10000; $i++) {
    after();
//}
