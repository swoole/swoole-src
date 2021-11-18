<?php

require_once __DIR__ . "/../../../include/bootstrap.php";

//swoole_function Swoole\Timer::after($ms, $callback, $param = null) {}
//swoole_function Swoole\Timer::tick($ms, $callback) {}
//swoole_function Swoole\Timer::clear($timer_id) {}

Swoole\Timer::after(-1, function(){ });
Swoole\Timer::tick(-1, function() { });
Swoole\Timer::after(86400001, function(){ });
Swoole\Timer::tick(86400001, function() { });
Swoole\Timer::clear(-1);

for ($i = 0; $i < 1000; $i++) {
    Swoole\Timer::clear(Swoole\Timer::after(1, function() {}));
}

//Swoole\Timer::after(1, null);
//Swoole\Timer::after(1, "strlen");

function sw_timer_pass_ref(&$ref_func) {
    Swoole\Timer::after(1, $ref_func);
}
$func = function() {};
sw_timer_pass_ref($func);
