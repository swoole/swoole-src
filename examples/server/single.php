<?php
//singal process singal thread
$server = new swoole_server('127.0.0.1', 9501, SWOOLE_BASE);

//$server->set(array('worker_num' => 4));

$server->on('Receive', function($serv, $fd, $reactor_id, $data) {
	echo $data;
});

$server->start();
