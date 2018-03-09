<?php
go(function () {
    $redis = new Co\Redis;
    $redis->connect('127.0.0.1', 6379);
    $res = $redis->request(['object', 'encoding', 'key1']);
    var_dump($res);
});