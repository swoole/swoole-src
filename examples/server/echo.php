<?php
$serv = new swoole_server("0.0.0.0", 9501);

$port = $serv->listen('127.0.0.1', 9502, SWOOLE_SOCK_UDP);
$port->on('packet', function($serv, $data, $addr){
    var_dump($serv, $data, $addr);
});

$serv->on('connect', function ($serv, $fd, $from_id){
	echo "[#".posix_getpid()."]\tClient@[$fd:$from_id]: Connect.\n";
});

$serv->on('receive', function (swoole_server $serv, $fd, $from_id, $data) {
	echo "[#".$serv->worker_id."]\tClient[$fd]: $data\n";
    if ($serv->send($fd, "hello\n") == false)
    {
        echo "error\n";
    }
});

$serv->on('close', function ($serv, $fd, $from_id) {
	echo "[#".posix_getpid()."]\tClient@[$fd:$from_id]: Close.\n";
});

$serv->start();

