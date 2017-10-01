<?php
$tm1 = swoole_timer_tick(1000, function () {
    echo "tick 1000ms. \n";
});

swoole_timer_tick(3000, function ($id) use ($tm1) {
    echo "tick , clear\n";
	swoole_timer_clear($id);
	swoole_timer_clear($tm1);
}); 
