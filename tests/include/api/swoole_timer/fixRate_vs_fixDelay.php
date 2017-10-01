<?php

function fixRate(callable $callable, $interval)
{
    return swoole_timer_tick($interval, $callable);
}

function fixDelay(callable $callable, $interval)
{
    return swoole_timer_after($interval, function() use($callable, $interval) {
        call_user_func($callable);
        fixDelay($callable, $interval);
    });
}

function randBlock()
{
    $n = mt_rand(0, 10);
    for ($i = 0; $i < 1000000 * $n; $i++) {}
}

/*
$t = microtime(true);
fixDelay(swoole_function() use(&$t) {
    echo number_format(microtime(true) - $t, 3), PHP_EOL;
    randBlock();
    $t = microtime(true);
}, 1000);
//*/
/*
1.007
1.005
1.005
1.004
1.003
1.004
1.002
1.006
1.006
1.005
1.004
1.002
1.006
1.004
1.002
*/


/*
$t = microtime(true);
fixRate(swoole_function() use(&$t) {
    echo number_format(microtime(true) - $t, 3), PHP_EOL;
    randBlock();
    $t = microtime(true);
}, 1000);
*/
/*
1.003
0.759
1.005
0.538
1.002
1.003
0.763
1.005
0.247
1.004
1.004
0.270
1.005
0.199
1.000
0.335
1.005
1.006
0.239
1.004
0.119
*/