<?php
Swoole\Timer::tick(2000, function($timerId) {
    echo "tick 2000ms\n";
});
