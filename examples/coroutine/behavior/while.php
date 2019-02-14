<?php
Swoole\Coroutine::set([
    'max_death_ms' => 5000,
]);
$s = microtime(1);
echo "start\n";
go(function () {
    echo "coro 1  start\n";
    $x = 5;
    $i = 0;
    while(!0) {
        $i ++;
        echo "coro 1 $i\n";
        sleep(1);
    }
});

go(function () {
    echo "coro 2  start\n";
    $x = 5;
    $i = 0;
    while(1) {
        $i ++;
        echo "coro 2 $i\n";
        sleep(1);
    }
});

$t = microtime(1);
$u = $t-$s;
echo "use time $u s\n";
go(function () {
    echo "----------------------\n";
});
echo "end\n";
