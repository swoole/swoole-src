<?php
// require  __DIR__ . "/coro_include.php";
use Swoole\Coroutine as co;
co::create(function () {
    $client = new Swoole\Coroutine\Client(SWOOLE_SOCK_TCP);
    $res = $client->connect('127.0.0.1', 9501, 10);
    var_dump($res);
    co::sleep(0.5);
    echo "OK\n";
});
echo "11";
// co::run();