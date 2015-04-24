<?php
for($i=0; $i < 100; $i++)
{
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
	$client->close();
}
