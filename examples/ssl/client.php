<?php
$client = new swoole_client(SWOOLE_SOCK_TCP | SWOOLE_SSL);

sleep(1);
if (!$client->connect('127.0.0.1', 9501, -1))
{
    exit("connect failed. Error: {$client->errCode}\n");
}
echo "connect ok\n";
sleep(1);

$client->send("hello world\r\n\r\n");
echo "send ok\n";

sleep(1);
echo $client->recv();
sleep(1);
