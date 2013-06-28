<?php
$client = new swoole_client(SWOOLE_SOCK_TCP, SWOOLE_SOCK_SYNC); //同步阻塞
$client->connect('127.0.0.1', 9501, 0.5, 0);
//$send = str_repeat("A", 956).str_repeat("B", 566).str_repeat("C", 900);
$client->send(str_repeat("A", 956));
$client->send(str_repeat("B", 566));
$client->send(str_repeat("C", 900));

$client->send("\r\n\r\n");
$data = $client->recv(9000, 0);
echo $data."\n";
echo "len=".strlen($data)."\n";
$client->close();
