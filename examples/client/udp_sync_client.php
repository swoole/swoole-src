<?php
$client = new swoole_client(SWOOLE_SOCK_UDP, SWOOLE_SOCK_SYNC);
$client->connect('127.0.0.1', 9502);
$client->send("admin");
echo $client->recv();

