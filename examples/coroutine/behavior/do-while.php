<?php
Swoole\Coroutine::set([
    'max_death_ms' => 2000,
    'death_loop_threshold' => 5,
]);
echo "start\n";
go(function () {
    echo "coro start\n";
    do{
        echo "111\n";
        sleep(1);
    } while(1);
});

go(function () {
    echo "222222\n";
});
echo "end\n";
