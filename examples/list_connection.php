<?php
$clients = array();

for($i = 0; $i < 16; $i++){
	$client = new swoole_client(SWOOLE_SOCK_TCP, SWOOLE_SOCK_SYNC); //同步阻塞
	$ret = $client->connect('127.0.0.1', 9501, 0.5);
	if(!$ret)
	{
		echo "#$i\tConnect fail.  errno=".$client->errCode;
		die("\n");
	}
	$clients[] = $client;
	usleep(10);
}
$clients[0]->send("show connect list");
$c15 = $clients[15];
$c15->close();

//unset($clients[15]);

sleep(1000);

