<?php
$client = new swoole_client(SWOOLE_SOCK_TCP, SWOOLE_SOCK_SYNC); //同步阻塞
$ret = $client->connect('127.0.0.1', 9501, 0.5);
if(!$ret)
{
	echo "#Connect failed.  errno=".$client->errCode;
	die("\n");
}

while(1)
{
	$ret = $client->send("hello\n");
	if($ret === false)
	{
		echo "send failed. errno=".$client->errCode.PHP_EOL;
	}
	echo $client->recv();
	sleep(3);
}
