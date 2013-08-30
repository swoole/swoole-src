<?php
$client = new swoole_client(SWOOLE_SOCK_TCP, SWOOLE_SOCK_SYNC); //同步阻塞
$_s = microtime(true);
if(!$client->connect('127.0.0.1', 9501))
{
	exit("connect fail\n");
}
for($i=0; $i<100; $i++)
{
	$client->send(str_repeat("A", 25).$i);
	$client->send(str_repeat("A", 26).$i);
	$client->send(str_repeat("A", 27).$i);
	//$ret = $client->send("GET / HTTP/1.1\r\n");
	//$client->send("Host: localhost\r\n");
	//$client->send("Connection: keep-alive\r\n");
	$client->send("\r\n\r\n");
	
	$data = $client->recv(1024, 0);
	if($data === false)
	{
		echo "#{$i} recv fail.break\n";
		break;
	}
	//echo "recv[$i]",$data,"\n";
}
echo "$i: ",$data,"\n";
echo "test ok. use".((microtime(true) - $_s)*1000)."ms\n";
