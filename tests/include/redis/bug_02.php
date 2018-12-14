<?php
go(function () {
    $redis = new co\Redis();
    $redis->connect(REDIS_SERVER_HOST, REDIS_SERVER_PORT);
    echo "connectd: ";
    var_dump($redis->connected);
    co::sleep(10);

    $rt = $redis->get("key");
    var_dump($rt, $redis->errCode, $redis->errMsg);

         echo "connectd: ";var_dump($redis->connected);

    swoole_timer_after(1000, function () use ($redis) {
             echo "connectd: ";var_dump($redis->connected);
        $rt = $redis->get("key");
        var_dump($rt);
    });
});

