<?php
$client = new swoole_client(SWOOLE_SOCK_TCP);
//$client = new swoole_client(SWOOLE_SOCK_UNIX_DGRAM, SWOOLE_SOCK_SYNC); //同步阻塞
//if (!$client->connect(dirname(__DIR__).'/server/svr.sock', 0, -1, 1))
if (!$client->connect('127.0.0.1', 9502, -1))
{
	exit("connect failed. Error: {$client->errCode}\n");
}

$client->send("hello world\n");
echo $client->recv();
$client->close();
exit;

for($i=0; $i < 1; $i ++)
{
	//if ($client->sendfile(__DIR__.'/test.txt') === false)
	if ($client->send(str_repeat("A", 8000)) === false)
	{
		echo "send failed. Error: {$client->errCode}\n";
		break;
	}
	usleep(2000);
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

