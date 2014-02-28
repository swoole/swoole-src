<?php
$client = new swoole_client(SWOOLE_TCP | SWOOLE_KEEP);
if(!$client->connect('127.0.0.1', 9501))
{
	exit("connect failed\n");
}
$client->send(str_repeat("A", 600));
$data = $client->recv(7000, 0);
if($data === false)
{
	echo "recv fail\n";
	break;
}
var_dump($data);
unset($client);



$client2 = new swoole_client(SWOOLE_TCP | SWOOLE_KEEP);
if(!$client2->connect('127.0.0.1', 9501))
{
	exit("connect failed\n");
}
$client2->send(str_repeat("A", 600));
$data = $client2->recv(7000, 0);
if($data === false)
{
	echo "recv fail\n";
	break;
}
var_dump($data);

