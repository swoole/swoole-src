<?php
$client = new swoole_client(SWOOLE_SOCK_UNIX_STREAM, SWOOLE_SOCK_ASYNC);

$client->on("connect", function (swoole_client $cli)
{
    $cli->send("GET / HTTP/1.1\r\n\r\n");
});

$client->on("receive", function (swoole_client $cli, $data)
{
    echo "Receive: $data";
    $cli->send(str_repeat('A', 100) . "\n");
});

$client->on("error", function (swoole_client $cli)
{
    echo "error: [" . $cli->errCode . "] " . socket_strerror($cli->errCode) . "\n";
});

$client->on("close", function (swoole_client $cli)
{
    echo "Connection close\n";
});

$client->connect(__DIR__ . '/svr.sock', 0, -1);

swoole_event_wait();
echo "exit\n";
