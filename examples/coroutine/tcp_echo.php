<?php
$serv = new swoole_server("0.0.0.0", 9501);
$serv->on('connect', function ($serv, $fd, $reactor_id){
	echo "[#".posix_getpid()."]\tClient@[$fd]: Connect.\n";
});
$serv->set(array(
    'worker_num' => 1,

));

$serv->on('receive', function (swoole_server $serv, $fd, $reactor_id, $data) {
	echo "[#".$serv->worker_id."]\tClient[$fd] receive data: $data\n";
	if ($serv->send($fd, "{$data}\n") == false)
	{
		echo "error\n";
	}
});

$serv->on('close', function ($serv, $fd, $reactor_id) {
	echo "[#".posix_getpid()."]\tClient@[$fd]: Close.\n";
});

$serv->start();
