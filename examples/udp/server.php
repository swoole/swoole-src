<?php
$server = new swoole_server('0.0.0.0', 9905, SWOOLE_PROCESS, SWOOLE_SOCK_UDP);
for ($i = 0; $i < 20; $i++)
{
    $server->listen('0.0.0.0', 9906 + $i, SWOOLE_SOCK_UDP);
}
$server->set(['worker_num' => 4]);

$server->on('Packet', function (swoole_server $serv, $data, $addr)
{
    $serv->sendto($addr['address'], $addr['port'], "Swoole: $data", $addr['server_socket']);
});

$server->start();
