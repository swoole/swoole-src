<?php
require __DIR__ . "/coro_include.php";
use Swoole\Coroutine as co;

echo "start\n";
co::create(function () {
    $client = new Swoole\Coroutine\Client(SWOOLE_SOCK_TCP);
    $res = $client->connect('127.0.0.1', 9501, 1);
    var_dump($res);
    if ($res) {
        echo ("connect success. Error: {$client->errCode}\n");
    }

    $res = $client->send("hello");
    echo "send res:" . var_export($res, 1) . "\n";
    $data = $client->recv();
    echo "recv data" . var_export($data, 1) . "\n";
});
echo "end\n";
