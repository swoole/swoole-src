<?php
go(function (){
    $redis = new Co\Redis;
    $redis->connect('127.0.0.1', 6379);
    $res = $redis->eval("return redis.call('get', 'key')");
    var_dump($res);
});