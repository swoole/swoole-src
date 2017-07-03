<?php
require_once __DIR__ . "/../../../include/bootstrap.php";

function query_timeout($host, $port)
{
    $redis = new swoole_redis();
    $redis->on("close", function () {
        echo "closed\n";
    });

    $redis->on("message", function () {
        echo "message\n";
    });

    $redis->on("timeout", function (swoole_redis $redis, $timeoutType) {
        assert($timeoutType === SWOOLE_ASYNC_RECV_TIMEOUT);
        echo "query timeout\n";
        $redis->close();
    });

    $redis->setQueryTimeout(1);

    $result = $redis->connect($host, $port, function (swoole_redis $redis) {
        $redis->setQueryTimeout(1);

        $redis->get("HELLO", function (\swoole_redis $redis, $result) {
            assert(false);
        });
    });
}