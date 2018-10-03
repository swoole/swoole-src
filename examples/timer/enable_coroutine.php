<?php
swoole_async_set([
    'enable_coroutine' => false
]);
swoole_timer_tick(1000, function () {
    $uid = Co::getuid();
    assert($uid === -1);
    echo "#{$uid}\n";
});
