<?php
$serv = new swoole_server("0.0.0.0", 9501);

$serv->on('connect', function ($serv, $fd, $from_id){
	echo "[#".posix_getpid()."]\tClient@[$fd:$from_id]: Connect.\n";
});

$serv->on('receive', function (swoole_server $serv, $fd, $from_id, $data) {
	echo "[#".$serv->worker_id."]\tClient[$fd]: $data\n";
    if ($serv->send($fd, "hello\n") == false)
    {
        echo "error\n";
    }
    $serv->close($fd);
});

$serv->on('close', function ($serv, $fd, $from_id) {
	echo "[#".posix_getpid()."]\tClient@[$fd:$from_id]: Close.\n";
});

$serv->start();

