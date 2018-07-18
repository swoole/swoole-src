<?php

go(function () {
    $chan = new \chan();
    \swoole_timer_after(1000, function()use (&$chan){
        $chan->push("data");
    });
    $readArr = [$chan];
    $writeArr = null;
    $type = \chan::select($readArr, $writeArr, 5);
    if ($type) {
        $result = $chan->pop();
        echo "recv :".$result."\n";
    } else {
        echo "timeout\n";
    }
});