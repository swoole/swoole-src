<?php

require_once __DIR__ . "/../../../include/bootstrap.php";

for ($j = 0; $j < 100; $j++) {
    Swoole\Timer::after(1, function() use($j){
        echo $j, "\n";
    });
}
