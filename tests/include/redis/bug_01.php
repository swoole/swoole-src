<?php
go(function () {
    $redis = new co\Redis();
    $redis->connect(REDIS_SERVER_HOST, REDIS_SERVER_PORT);
    while (true)
    {
        $val = $redis->subscribe(['test']);
        var_dump($val);
        if (!$val) {
            break;
        }
    }
});
