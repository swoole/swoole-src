<?php
$client = new swoole_client(SWOOLE_SOCK_UDP, SWOOLE_SOCK_SYNC);
$client->connect('127.0.0.1', 9905);
$client->send(serialize(['hello' => str_repeat('A', 600), 'rand' => rand(1, 100)]));
echo $client->recv() . "\n";
sleep(1);
