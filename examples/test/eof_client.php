<?php
require __DIR__ . '/TestServer.php';

$client = new swoole_client(SWOOLE_SOCK_TCP);
if (!$client->connect('127.0.0.1', 9501))
{
    exit("connect failed\n");
}

for ($i = 0; $i < TestServer::PKG_NUM; $i++)
{
    $len = TestServer::random();
    $sid = TestServer::random();

    $array['index'] = $i;
    $array['sid'] = $sid;
    $array['len'] = $len;
    $array['data'] = str_repeat('A', $len);
    $_send = serialize($array) . "\r\n\r\n";

    if ($i % 1000 == 0)
    {
        echo "#{$i} send package. sid={$sid}, length=" . strlen($_send) . "\n";
        //usleep(100);
    }

    if (!$client->send($_send))
    {
        break;
    }
}
sleep(1);
