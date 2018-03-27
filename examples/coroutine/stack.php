<?php
co::set(['stack_size' => 8192*4]);

function test($n)
{
    $a = 1;
    $b = 2;
    $c = 3;
    $d = 4;
    static $i;

    usleep(100000);
    echo "index=".($i++)."\n";

    return test($n + $a + $b + $c + $d);
}

go(function () {
    test(9);
});
