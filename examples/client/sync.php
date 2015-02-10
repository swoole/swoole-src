<?php
$client = new swoole_client(SWOOLE_SOCK_TCP);
//$client = new swoole_client(SWOOLE_SOCK_UNIX_DGRAM, SWOOLE_SOCK_SYNC); //同步阻塞
//if (!$client->connect(dirname(__DIR__).'/server/svr.sock', 0, -1, 1))
if (!$client->connect('127.0.0.1', 9501, -1))
{
	exit("connect failed. Error: {$client->errCode}\n");
}

for($i=0; $i < 10; $i ++)
{
    $client->send("hello world\n");
    echo $client->recv();
    usleep(2000);
}

$client->close();