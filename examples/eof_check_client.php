<?php
$client = new swoole_client(SWOOLE_SOCK_TCP);
if(!$client->connect('127.0.0.1', 9501))
{
    exit("connect failed\n");
}

$client->send(str_repeat('A', 8192));
$client->send(str_repeat('B', 5000));
$client->send("\r\n\r\n");
$data = $client->recv();
var_dump($data);
