<?php
require __DIR__ . "/coro_include.php";
echo "before coro\n";
go(function () {
    echo "co[1] start\n";

    $client = new Swoole\Coroutine\Client(SWOOLE_SOCK_TCP);
    $res = $client->connect('127.0.0.1', 9501, 1);
    echo "co[1] connect ret = ".var_export($res,1)."\n";
    co::sleep(1);
    $res = $client->send("hello world\n");
    echo "co[1] send ret = ".var_export($res,1)."\n";
    $res =  $client->recv();
    echo "co[1] recv ret = ".var_export($res,1)."\n";
    echo "co[1] exit\n";
});
echo "out coro \n";
