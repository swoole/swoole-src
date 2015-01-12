<?php
$client = new swoole_client(SWOOLE_SOCK_TCP); //同步阻塞
if(empty($argv[1]))
{
	$loop = 1;
}
else
{
	$loop = intval($argv[1]);
}

$_s = microtime(true);
if(!$client->connect('127.0.0.1', 9501))
{
	exit("connect fail\n");
}

for($i=0; $i<$loop; $i++)
{
	$client->send(str_repeat("A", 8000).$i."[0]");
	//$client->send(str_repeat("A", 20).$i."[1]");
	//$client->send(str_repeat("A", 30).$i."[2]");
	//$ret = $client->send("GET / HTTP/1.1\r\n");
	//$client->send("Host: localhost\r\n");
	//$client->send("Connection: keep-alive\r\n");
	$client->send("\r\n\r\n");
	
	//$data = $client->recv(1024, 0);
	//if($data === false)
	//{
	//	echo "#{$i} recv fail.break\n";
//		break;
//	}
	//echo "recv[$i]",$data,"\n";
}

sleep(1000);
echo "$i: ",$data,"\n";
echo "test ok. use".((microtime(true) - $_s)*1000)."ms\n";
