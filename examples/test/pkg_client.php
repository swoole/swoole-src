<?php
require __DIR__.'/TestServer.php';

$client = new swoole_client(SWOOLE_SOCK_TCP);
if (!$client->connect('127.0.0.1', 9501))
{
    exit("connect failed\n");
}

$data = '';
for ($i = 0; $i < TestServer::PKG_NUM; $i++)
{
    $len = rand(10000, 20000);
//    $len = 10240;
    $sid = rand(10000, 99999);

    if ($i % 1000 == 0)
    {
        echo "#{$i} send package. sid={$sid}, length=" . ($len + 10) . "\n";
        //usleep(100);
    }

    $data = pack('nNN', $len + 8, $i, $sid);
    $data .= str_repeat('A', $len);
    if (!$client->send($data))
    {
        break;
    }
}

sleep(1);
