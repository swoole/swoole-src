<?php
$client = new swoole_client(SWOOLE_SOCK_TCP, SWOOLE_SOCK_SYNC); //同步阻塞
if (!$client->connect('127.0.0.1', 9501, -1))
{
	exit("connect failed. Error: {$client->errCode}\n");
}
//if ($client->sendfile(__DIR__.'/test.txt') === false)
if ($client->send(str_repeat("A", 600)) === false)
{
	echo "send failed. Error: {$client->errCode}\n";
	break;
}
$data = $client->recv(7000);
if ($data === false)
{
	echo "recv failed. Error: {$client->errCode}\n";
	break;
}
//var_dump($data);

//$data = $client->recv(7000);

var_dump($data);
$client->close();

