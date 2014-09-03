<?php
$client = new swoole_client(SWOOLE_SOCK_TCP, SWOOLE_SOCK_SYNC); //同步阻塞
if (!$client->connect('127.0.0.1', 9501, -1))
{
	exit("connect failed. Error: {$client->errCode}\n");
}
for($i=0; $i < 100; $i ++)
{
	//if ($client->sendfile(__DIR__.'/test.txt') === false)
	if ($client->send(str_repeat("A", 8000)) === false)
	{
		echo "send failed. Error: {$client->errCode}\n";
		break;
	}
	usleep(20000);
}
sleep(10000);
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
var_dump($client->isConnected());
//var_dump($data);

//$data = $client->recv(7000);

var_dump($data);
$client->close();
var_dump($client->isConnected());

