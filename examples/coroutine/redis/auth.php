<?php
go(function () {
    $redis = new Swoole\Coroutine\Redis;
    $redis->connect('127.0.0.1', 6379);
    $redis->auth('root');
    $redis->set('key', 'swoole redis work');
    var_dump($redis->get('key'));
});
