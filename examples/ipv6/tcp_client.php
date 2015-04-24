<?php
$client = new swoole_client(SWOOLE_SOCK_TCP6);
if (!$client->connect('::1', 9501, -1))
{
	exit("connect failed. Error: {$client->errCode}\n");
}

var_dump($client->getsockname());

for($i=0; $i < 1; $i ++)
{
    $client->send("hello world\n");
    echo $client->recv();
    usleep(2000);
}

$client->close();