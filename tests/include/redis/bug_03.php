<?php


go(function () use ($redis) {

    $redis = new co\Redis();
    $redis->connect('127.0.0.1', 6379);


    go(function () use ($redis) {
        var_dump($redis->get("key"));
    });

    go(function() use ($redis) {

        co::sleep(1);
        var_dump($redis->get("key"));
    });

});

