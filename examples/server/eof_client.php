<?php
$client = new swoole_client(SWOOLE_SOCK_TCP, SWOOLE_SOCK_SYNC); //同步阻塞
if(!$client->connect('127.0.0.1', 9501, 0.5, 0))
{
	echo "Over flow. errno=".$client->errCode;
	die("\n");
}

$data = array(
	'name' => __FILE__,
	'content' => str_repeat('A', 8192 * 180),  //800K
);

if(!$client->send(serialize($data)."\r\n\r\n"))
{
	die("send failed.\n");
}

sleep(10);
