<?php
$client = new swoole_redis;

$client->on('message', function (swoole_redis $client, $result) {
    var_dump($result);
    static $more = false;
    if (!$more and $result[0] == 'message')
    {
        echo "subscribe new channel\n";
        $client->subscribe('msg_1', 'msg_2');
        $client->unsubscribe('msg_0');
        $more = true;
    }
});

$client->connect('127.0.0.1', 6379, function (swoole_redis $client, $result) {
    echo "connect\n";
    $client->subscribe('msg_0');
});
