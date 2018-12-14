<?php
const REDIS_SERVER_HOST = '127.0.0.1';
const REDIS_SERVER_PORT = 6379;


go(function () {
    $redis = new Swoole\Coroutine\Redis();
    $redis->connect(REDIS_SERVER_HOST, REDIS_SERVER_PORT);
    $redis->setDefer();
    $redis->set('key1', 'value');
    $redis->get('key1');

    $result1 = $redis->recv();
    $result2 = $redis->recv();

    var_dump($result1, $result2);
});


