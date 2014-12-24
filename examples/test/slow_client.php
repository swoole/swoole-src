<?php
$client = new swoole_client(SWOOLE_SOCK_TCP, SWOOLE_SOCK_SYNC); //同步阻塞
if(!$client->connect('127.0.0.1', 9501))
{
    exit("connect failed\n");
}

$data = $client->recv();
echo "recv ".strlen($data)." bytes\n";
sleep(1);

for ($i = 0; $i < 500; $i++)
{
    $data .= $client->recv();

    if (strlen($data) == 4000000) break;
}
echo "recv ".strlen($data)." bytes\n";

sleep(1000);