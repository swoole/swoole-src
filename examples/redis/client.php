<?php
$client = new swoole_redis;
$client->connect('127.0.0.1', 6379, function (swoole_redis $client, $result) {
    $client->execute('SET key swoole', function (swoole_redis $client, $result) {
        var_dump($client, $result);
        $client->execute('get key', function (swoole_redis $client, $result) {
            var_dump($client, $result);
            $client->close();
        });
    });
});
