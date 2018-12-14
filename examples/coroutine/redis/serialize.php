<?php

go(function () {
    $redis = new \Swoole\Coroutine\Redis;
    $redis->connect('127.0.0.1', 6379, true); // param3 is serialize
    $redis->set('foo', ['bar' => 'baz']);
    $ret = $redis->get('foo');
    var_dump($ret);
});
