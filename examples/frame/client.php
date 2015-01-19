<?php
$client = new swoole_client(SWOOLE_TCP | SWOOLE_FRAME);

if (!$client->connect('127.0.0.1', 9501, -1))
{
    exit("connect failed. Error: {$client->errCode}\n");
}

$client->send("hello world\n");
echo $client->recv();
$client->close();

