<?php
const N = 10000000;

$s = microtime(true);

$cid = go(function () {
    $n = N / 2;
    while ($n--) {
        co::yield();
    }
    echo "co[" . Co::getCid() . "] end\n";
});

go(function () use ($cid) {
    $n = N / 2;
    while ($n--) {
        co::resume($cid);
    }
    echo "co[" . Co::getCid() . "] end\n";
});

$e = microtime(true);
echo "switch " . N . " times, takes " . round(($e - $s) * 1000, 2) . "ms\n";
echo "switch time =  " . round(($e - $s) / N * (1000 * 1000 * 1000), 2) . "ns\n";