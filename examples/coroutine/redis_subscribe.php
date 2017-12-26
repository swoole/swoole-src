<?php

use Swoole\Coroutine as co;

co::create(function () {
    $redis = new co\Redis();
    $redis->connect('127.0.0.1', 6379);
    while (true)
    {
        $val = $redis->subscribe(['test']);
        //订阅的channel，以第一次调用subscribe时的channel为准，后续的subscribe调用是为了收取Redis Server的回包
        //如果需要改变订阅的channel，请close掉连接，再调用subscribe
        var_dump($val);
    }
});