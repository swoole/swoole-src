<?php

swoole_async_set([
    'enable_coroutine' => false,
]);
swoole_timer_tick(1000, function () {
    $uid = Co::getuid();
    assert(-1 === $uid);
    echo "#{$uid}\n";
});
