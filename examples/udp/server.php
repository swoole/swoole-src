<?php
$server = new swoole_server('0.0.0.0', 9905, SWOOLE_PROCESS, SWOOLE_SOCK_UDP);
$server->set(['worker_num' => 1]);
$server->on('Packet', function (swoole_server $serv, $data, $addr)
{
    $serv->sendto($addr['address'], $addr['port'], "Swoole: $data");
    var_dump( $addr, strlen($data));
});
//$server->on('receive', function (swoole_server $serv, $fd, $reactor_id, $data)
//{
//    var_dump($data);
//    var_dump($serv->connection_info($fd, $reactor_id));
//});
$server->start();
