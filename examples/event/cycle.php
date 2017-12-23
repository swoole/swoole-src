<?php

Swoole\Timer::tick(2000, function ($id) {
	var_dump($id);
});

Swoole\Event::cycle(function () {
	echo "hello [1]\n";
    Swoole\Event::cycle(function () {
	    echo "hello [2]\n";
        Swoole\Event::cycle(null);
    });
});
