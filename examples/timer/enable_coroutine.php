<?php
swoole_async_set([
    'enable_coroutine' => false
]);
Swoole\Timer::tick(1000, function () {
    $uid = Co::getuid();
    assert($uid === -1);
    echo "#{$uid}\n";
});
