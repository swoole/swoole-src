<?php
Swoole\Coroutine::set([
    'max_death_ms' => 5000,
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
