<?php
$client = new swoole_client(SWOOLE_SOCK_TCP);

if (!$client->connect('127.0.0.1', 8089, -1))
{
    exit("connect failed. Error: {$client->errCode}\n");
}

function _send(swoole_client $client, $data)
{
    return $client->send(pack('N', strlen($data)) . $data);
}

var_dump($client->getsockname());


_send($client, "hello world");
_send($client, "hello world [2]");

$client->close();
