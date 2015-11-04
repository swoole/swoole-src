<?php
$server = new swoole_server('0.0.0.0', 9905, SWOOLE_PROCESS, SWOOLE_SOCK_UDP);
$server->set(['worker_num' => 1]);
$socket = $server->getSocket();

$ret = socket_set_option(
    $socket,
    IPPROTO_IP,
    MCAST_JOIN_GROUP,
    array('group' => '224.10.20.30', 'interface' => 0)
);

if ($ret === false)
{
    throw new RuntimeException('Unable to join multicast group');
}

$server->on('Packet', function (swoole_server $serv, $data, $addr)
{
    $serv->sendto($addr['address'], $addr['port'], "Swoole: $data");
    var_dump( $addr, strlen($data));
});

$server->start();
