<?php

require_once __DIR__ . "/../../../include/bootstrap.php";

//swoole_function Swoole\Timer::after($ms, $callback, $param = null) {}
//swoole_function Swoole\Timer::tick($ms, $callback) {}
//swoole_function Swoole\Timer::clear($timer_id) {}


function after()
{
    $start = microtime(true);
    Swoole\Timer::after(1000, function() use($start) {
        echo microtime(true) - $start, "\n";
        after();
    });
}

//for ($i = 0; $i < 10000; $i++) {
    after();
//}
