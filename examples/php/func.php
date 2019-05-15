<?php
declare(ticks=10);
function test()
{
    echo "start\n";
    $i = 0;
    while ($i < 10000) {
        $i++;
    }
    echo "end\n";
}