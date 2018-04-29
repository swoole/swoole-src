<?php
go(function () {
    $redis = new co\Redis();
    $redis->connect('127.0.0.1', 6379);
    while (true)
    {
        $val = $redis->subscribe(['test']);
        var_dump($val);
        if (!$val) {
            break;
        }
    }
});
