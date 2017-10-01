<?php
for($i = 0; $i < 100; $i++) {
    Swoole\Coroutine::create(function() use ($i) {
        $redis = new Swoole\Coroutine\Redis();
        $res = $redis->connect('127.0.0.1', 6379);
        $ret = $redis->incr('coroutine');
        $redis->close();
        if ($i == 50) {
            Swoole\Coroutine::create(function() use ($i) {
                $redis = new Swoole\Coroutine\Redis();
                $res = $redis->connect('127.0.0.1', 6379);
                $ret = $redis->set('coroutine_i', 50);
                $redis->close();
            });
        }
    });
}
