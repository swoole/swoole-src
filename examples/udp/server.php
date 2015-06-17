<?php
$server = new swoole_server('0.0.0.0', 9905, SWOOLE_PROCESS, SWOOLE_SOCK_UDP);
$server->on('Packet', function (swoole_server $serv, $data, $addr)
{
    $serv->sendto($addr['address'], $addr['port'], "Swoole: $data");
    var_dump($data, $addr);
});
$server->start();
