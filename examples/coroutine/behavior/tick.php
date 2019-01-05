<?php
declare(ticks=1);

// A function called on each tick event
function tick_handler()
{
    echo "tick_handler() called\n";
}
register_tick_function('tick_handler');

function tick_handler1()
{
    echo "tick_handler()11 called\n";
}
register_tick_function('tick_handler1');
$a = 1;
$a = 1;
$a = 1;

$a = 1;
$a = 1;
$a = 1;
$a = 1;

if ($a > 0) {
    $a += 2;
    print($a);
}

