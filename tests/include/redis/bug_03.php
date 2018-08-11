<?php


go(function () use ($redis) {

    $redis = new co\Redis();
    $redis->connect(REDIS_SERVER_HOST, REDIS_SERVER_PORT);


    go(function () use ($redis) {
        var_dump($redis->get("key"));
    });

    go(function() use ($redis) {

        co::sleep(1);
        var_dump($redis->get("key"));
    });

});

