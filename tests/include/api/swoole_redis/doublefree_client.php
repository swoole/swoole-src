<?php

function get(\swoole_redis $redis)
{
    // TODO 为什么需要timer，否则call返回false TIMER ???
    swoole_timer_after(1, function() use($redis) {
        $r = $redis->get("HELLO", function(\swoole_redis $redis, $result) {
            var_dump($result);
            get($redis);
        });
        assert($r);
        $redis->close();
        test();
    });
}

function test()
{
    $redis = new \swoole_redis();
    $redis->on("close", function(\swoole_redis $redis) {
        echo "close\n\n";
        test();
        // 死循环
        // $swoole_redis->close();
    });

    $redis->connect("127.0.0.1", 6379, function(\swoole_redis $redis, $connected) {
        assert($connected);
        // get($swoole_redis);
        $redis->get("HELLO", function(\swoole_redis $redis, $result) {});
    });
}

test();
return;

function test1() {
    $redis = new \swoole_redis();
    $redis->on("close", function() { echo "close"; });

    $redis->connect("127.0.0.1", 6379, function(\swoole_redis $redis, $connected) {
        assert($connected);

        swoole_timer_after(1, function() use($redis) {
            $r = $redis->get("HELLO", function(\swoole_redis $redis, $result) {
                var_dump($redis);
                var_dump($result);
                test();
            });
            assert($r);
            swoole_timer_after(1, function() use($redis) {
//                $r = $swoole_redis->close();
//                var_dump($r);
//                $swoole_redis->close();
            });
        });
    });
}

test1();

