<?php
$client = new swoole_client(SWOOLE_SOCK_UDP, SWOOLE_SOCK_SYNC);
$client->connect('127.0.0.1', 9905, -1);
$socket = $client->getSocket();

$ret = socket_set_option(
    $socket,
    IPPROTO_IP,
    MCAST_JOIN_GROUP,
    array('group' => '224.10.20.30', 'interface' => 0)
);

while(true)
{
    echo $client->recv() . "\n";
}

sleep(1);
