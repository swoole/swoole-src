<?php
$tm1 = Swoole\Timer::tick(1000, function () {
    echo "tick 1000ms. \n";
});

Swoole\Timer::tick(3000, function ($id) use ($tm1) {
    echo "tick , clear\n";
	Swoole\Timer::clear($id);
	Swoole\Timer::clear($tm1);
});
