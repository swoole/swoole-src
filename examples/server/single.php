<?php
//single process single thread
$server = new Swoole\Server('127.0.0.1', 9501, SWOOLE_BASE);

$server->on('Receive', function($serv, $fd, $reactor_id, $data) {
	$serv->send($fd, "Swoole: $data");
});

$server->start();
