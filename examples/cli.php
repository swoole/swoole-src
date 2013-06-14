<?php
$client = new swoole_client(SWOOLE_SOCK_TCP, SWOOLE_SOCK_SYNC); //同步阻塞
$client->connect('127.0.0.1', 9501, 0.5, 0);
for($i=0; $i< 3; $i++)
{
	$client->send("hello world-{$i}");
}
$client->send("\r\n\r\n");
$data = $client->recv(1024, 0);
echo $data."\n";
$client->close();
