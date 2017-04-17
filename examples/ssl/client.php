<?php
$client = new swoole_client(SWOOLE_SOCK_TCP | SWOOLE_SSL);
if (!$client->connect('192.168.0.44', 9501, -1))
{
    exit("connect failed. Error: {$client->errCode}\n");
}
echo "connect ok\n";
sleep(1);

for ($i = 0; $i < 1000; $i++)
{
    $client->send("hello world-" . str_repeat('A', $i) . "\n");
    echo $client->recv();
}
sleep(1);
