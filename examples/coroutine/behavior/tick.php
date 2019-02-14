<?php
declare(ticks=1);

Swoole\Coroutine::set([
    'max_exec_msec' => 10,
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
        sleep(0.5);
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