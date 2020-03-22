<?php
//Swoole\Async::set(array('enable_reuse_port' => true));
//$serv = new swoole_server("0.0.0.0", 9502, SWOOLE_BASE, SWOOLE_SOCK_UDP);
$serv = new Swoole\Server("0.0.0.0", 9502, SWOOLE_PROCESS, SWOOLE_SOCK_UDP);
$serv->set(
    array(
        'dispatch_mode' => 1,
        'enable_reuse_port' => true,
        'worker_num' => 8,    //worker process num
//    //'log_file' => '/tmp/swoole.log',
//    //'daemonize' => true,
    )
);

function my_onStart($serv)
{
    echo "MasterPid={$serv->master_pid}|Manager_pid={$serv->manager_pid}\n";
    echo "Server: start.Swoole version is [" . SWOOLE_VERSION . "]\n";
}

function my_onPacket(swoole_server $serv, $data, $addr)
{
//    var_dump($addr);
    $serv->sendto($addr['address'], $addr['port'], 'Swoole: ' . $data);
}

$serv->on('Start', 'my_onStart');
$serv->on('Packet', 'my_onPacket');
$serv->start();
