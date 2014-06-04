<?php
/**
 * This is the pseudo code, Not implemented
 */ 
$serv = new swoole_server('127.0.0.1', 9501);

$serv->on('connect', function($serv, $fd, $from_id) {
	$coroutine = new swoole_thread("thread_start");
	$coroutine->serv = $serv;
	$coroutine->fd = $fd;
	$coroutine->start();
	
});

$serv->start();

function thread_start(swoole_thread $coroutine)
{
	$serv = $coroutine->serv;
	$data = $serv->recv($fd);
	
	$socket = new swoole_client(SWOOLE_SOCK_TCP);
	if ($socket->connect('127.0.0.1', 9502, 0.5))
	{
		$socket->send("request\n");
		$response = $socket->recv();
	}
	$socket->close();	
	$serv->send($fd, "Server: {$response }\n");
}
