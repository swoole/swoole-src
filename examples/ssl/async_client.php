<?php
$client = new swoole_client(SWOOLE_SOCK_TCP | SWOOLE_SSL, SWOOLE_SOCK_ASYNC); //异步非阻塞
$client->on("connect", function (swoole_client $cli)
{
    $cli->send("Hello World\n");
});

$client->on("receive", function (swoole_client $cli, $data)
{
    echo "Receive: $data";
    $cli->close();
});

$client->on("error", function (swoole_client $cli)
{
    echo "error\n";
});

$client->on("close", function (swoole_client $cli)
{
    echo "Connection close\n";
});

$client->connect('127.0.0.1', 9501);
echo "connect to 127.0.0.1:9501\n";
