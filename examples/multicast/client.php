<?php
$client = new swoole_client(SWOOLE_SOCK_UDP, SWOOLE_SOCK_SYNC);
$client->connect('224.10.20.30', 9905);
$client->send("hello world");
echo $client->recv() . "\n";
sleep(1);
