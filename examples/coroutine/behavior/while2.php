<?php
Swoole\Coroutine::set([
    'max_death_ms' => 5000,
]);
$s = microtime(1);
echo "start\n";

$flag = 1;
go(function () use (&$flag){
    echo "coro 1 start\n";
    $i = 0;
    while($flag) {
        $i ++;
        echo "$i\n";
        sleep(1);
    }
    echo "coro 1 can exit\n";
});

$t = microtime(1);
$u = $t-$s;
echo "use time $u s\n";
go(function () use (&$flag){
    echo " coro 2 set flag = false\n";
    $flag = false;
});
echo "end\n";
