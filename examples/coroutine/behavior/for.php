<?php
co::set(['enable_preemptive_scheduler' => true]);
$start = microtime(1);
echo "start\n";
$flag = 1;

go(function () use (&$flag) {    
    echo "coro 1 start to loop\n";
    $i = 0;
    for (;;) {
//         echo "$i\n";
        if (!$flag) {
            break;
        }
        $i++;
    }
    echo "coro 1 can exit\n";
});
    
$end = microtime(1);
$msec = ($end - $start) * 1000;
echo "use time $msec\n";
go(function () use (&$flag) {
    echo "coro 2 set flag = false\n";
    $flag = false;
});
echo "end\n";