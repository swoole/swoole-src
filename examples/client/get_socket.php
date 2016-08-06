<?php

function getClient()
{
    $client = new swoole_client(SWOOLE_SOCK_TCP);
    if (!$client->connect('127.0.0.1', 9501, -1))
    {
        exit("connect failed. Error: {$client->errCode}\n");
    }

    $res = $client->getSocket();
    return $client;
}

$client = getClient();

$count = 0;
//$client->set(array('open_eof_check' => true, 'package_eof' => "\r\n\r\n"));

//$client = new swoole_client(SWOOLE_SOCK_UNIX_DGRAM, SWOOLE_SOCK_SYNC); //同步阻塞
//if (!$client->connect(dirname(__DIR__).'/server/svr.sock', 0, -1, 1))


var_dump($client->getsockname());
$client->send("hello world\r\n\r\n");

//for($i=0; $i < 3; $i ++)
{
    echo $client->recv();
    sleep(1);
}

$client->close();

