<?php
$serv = new swoole_server("0.0.0.0", 9501, SWOOLE_PROCESS, SWOOLE_SOCK_TCP | SWOOLE_SSL);
$key_dir = dirname(dirname(__DIR__)).'/tests/ssl';

//$serv->addlistener('0.0.0.0', 9502, SWOOLE_SOCK_TCP);

$serv->set(array(
	'worker_num' => 4,
	'ssl_cert_file' => $key_dir.'/ssl.crt',
	'ssl_key_file' => $key_dir.'/ssl.key',
));

$serv->on('connect', function ($serv, $fd, $from_id){
	echo "[#".posix_getpid()."]\tClient@[$fd:$from_id]: Connect.\n";
});

$serv->on('receive', function (swoole_server $serv, $fd, $from_id, $data) {
	echo "[#".posix_getpid()."]\tClient[$fd]: $data\n";
	$serv->send($fd, "Swoole: $data\n");
});

$serv->on('close', function ($serv, $fd, $from_id) {
	echo "[#".posix_getpid()."]\tClient@[$fd:$from_id]: Close.\n";
});

$serv->start();

