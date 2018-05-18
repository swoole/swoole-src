<?php
require __DIR__ . "/coro_include.php";
echo "before coro\n";
go(function () {
    echo "co[1] start\n";
    go(function () {
        echo "co[2] start\n";
        $client = new Swoole\Coroutine\Client(SWOOLE_SOCK_TCP);
        $res = $client->connect('127.0.0.1', 9501, 1);    
        echo "co[2] resume : connect ret = ".var_export($res,1)."\n";
        echo "co[2] exit\n";
    });
    $client = new Swoole\Coroutine\Client(SWOOLE_SOCK_TCP);
    $res = $client->connect('127.0.0.1', 9501, 1);        
    echo "co[1] resume : connect ret = ".var_export($res,1)."\n";
    echo "co[1] exit\n";
});
echo "out coro \n";
