<?php
$serv = new swoole_server("0.0.0.0", 9501, SWOOLE_BASE);

$port = $serv->listen('127.0.0.1', 9502, SWOOLE_SOCK_UDP);
$port->on('packet', function($serv, $data, $addr){
    var_dump($serv, $data, $addr);
});

$port2 = $serv->listen('127.0.0.1', 9503, SWOOLE_SOCK_TCP);
$port2->on('receive', function (swoole_server $serv, $fd, $reactor_id, $data) {
    echo "PORT-9503\t[#".$serv->worker_id."]\tClient[$fd]: $data\n";
    if ($serv->send($fd, "hello\n") == false)
    {
        echo "error\n";
    }
});

$serv->on('connect', function ($serv, $fd, $reactor_id){
	echo "[#".posix_getpid()."]\tClient@[$fd:$reactor_id]: Connect.\n";
});

$serv->on('receive', function (swoole_server $serv, $fd, $reactor_id, $data) {
	echo "[#".$serv->worker_id."]\tClient[$fd]: $data\n";
    if ($serv->send($fd, "hello\n") == false)
    {
        echo "error\n";
    }
});

$serv->on('close', function ($serv, $fd, $reactor_id) {
	echo "[#".posix_getpid()."]\tClient@[$fd:$reactor_id]: Close.\n";
});

$serv->start();
