<?php
$client = new swoole_client(SWOOLE_SOCK_TCP, SWOOLE_SOCK_SYNC); //同步阻塞
if(!$client->connect('127.0.0.1', 9501, 0.5, 0))
{
	echo "Over flow. errno=".$client->errCode;
	die("\n");
}

$data = array(
	'name' => __FILE__,
	'content' => str_repeat('A', 8192 * rand(1, 3)),  //800K
);

$_serialize_data = serialize($data);

$_send = $_serialize_data."\r\n";

echo "serialize_data length=".strlen($_serialize_data)."send length=".strlen($_send)."\n";

if(!$client->send($_send))
{
	die("send failed.\n");
}

$client->send("\r\n".substr($_serialize_data, 0, 8000));

//echo $client->recv();

$client->send(substr($_serialize_data, 8000));

//usleep(500000);

if (!$client->send("\r\n\r\n"))
{
	die("send failed.\n");
}

echo $client->recv();

//sleep(1);
