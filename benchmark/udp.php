<?php
//Swoole\Async::set(array('enable_reuse_port' => true));
//$serv = new swoole_server("0.0.0.0", 9502, SWOOLE_BASE, SWOOLE_SOCK_UDP);
$serv = new swoole_server("0.0.0.0", 9502, SWOOLE_PROCESS, SWOOLE_SOCK_UDP);
$serv->set(array(
    'dispatch_mode' => 1,
    'worker_num' => 8,    //worker process num
//    //'log_file' => '/tmp/swoole.log',
//    //'daemonize' => true,
));

function my_onStart($serv)
{
    echo "MasterPid={$serv->master_pid}|Manager_pid={$serv->manager_pid}\n";
    echo "Server: start.Swoole version is [" . SWOOLE_VERSION . "]\n";
}

function my_onReceive(swoole_server $serv, $fd, $from_id, $data)
{
    //var_dump($serv->connection_info($fd, $from_id));
    //echo "worker_pid=".posix_getpid().PHP_EOL;
    //var_dump($fd, $from_id);
    $serv->send($fd, 'Swoole: ' . $data, $from_id);
}

function my_onPacket(swoole_server $serv, $data, $addr)
{
//    var_dump($addr);
    $serv->sendto($addr['address'], $addr['port'], 'Swoole: ' . $data);
}

$serv->on('Start', 'my_onStart');
$serv->on('Receive', 'my_onReceive');
//$serv->on('Packet', 'my_onPacket');
$serv->start();

