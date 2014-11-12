<?php
//single process single thread
$server = new swoole_server('127.0.0.1', 9501, SWOOLE_BASE);

$server->on('Receive', function($serv, $fd, $reactor_id, $data) {
	$serv->send($fd, "Swoole: $data");
});

$server->start();
