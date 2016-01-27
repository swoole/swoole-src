<?php
$client = new swoole_redis;
$client->connect('127.0.0.1', 6379, function (swoole_redis $client, $result) {
    echo "connect\n";
    $client->set('key', 'swoole', function (swoole_redis $client, $result) {
        echo "set key OK\n";
        $client->get('key', function (swoole_redis $client, $result) {
            var_dump($result);
            $client->keys('*', function (swoole_redis $client, $result) {
                var_dump($result);
                $client->close();
            });
        });
    });
});
