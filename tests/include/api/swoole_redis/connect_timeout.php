<?php
$redis = new swoole_redis();
$redis->on("close", function (){
    echo "closed\n";
});

$redis->on("message", function (){
    echo "message\n";
});

$result = $redis->connect("192.1.1.1", 9000, function ($redis, $result)
{
    assert($redis->errCode == SOCKET_ETIMEDOUT);
    assert($result === false);
});
