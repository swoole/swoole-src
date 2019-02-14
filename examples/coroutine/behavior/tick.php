<?php
declare(ticks=10);

$max_msec = 10;
Swoole\Coroutine::set([
    'max_exec_msec' => $max_msec,
]);

$s = microtime(1);
echo "start\n";
$flag = 1;
go(function () use (&$flag, $max_msec){
    echo "coro 1 start to loop for $max_msec msec\n";
    $i = 0;
    while($flag) {
        echo "$i\n";
        $i ++;
    }
    echo "coro 1 can exit\n";
});
    
$t = microtime(1);
$u = $t-$s;
echo "use time $u s\n";
go(function () use (&$flag){
    echo "coro 2 set flag = false\n";
    $flag = false;
});
echo "end\n";
swoole_event_wait();