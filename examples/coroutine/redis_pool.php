<?php

$count = 0;
$pool = new SplQueue();
$server = new Swoole\Http\Server('127.0.0.1', 9501, SWOOLE_BASE);

$server->on('Request', function ($request, $response) use (&$count, $pool) {
    if (0 == count($pool)) {
        $redis = new Swoole\Coroutine\Redis();
        $res = $redis->connect('127.0.0.1', 6379);
        if (false == $res) {
            $response->end('redis connect fail!');

            return;
        }
        $pool->push($redis);
    }
    $redis = $pool->pop();
    ++$count;
    $ret = $redis->set('key', 'value');
    $response->end("swoole response is ok, count = $count, result=".var_export($ret, true));
    $pool->push($redis);
});

$server->start();
