<?php
//$serv = new swoole_server("0.0.0.0", 9501, SWOOLE_BASE, SWOOLE_SOCK_TCP | SWOOLE_SSL);
$serv = new swoole_server("0.0.0.0", 9501, SWOOLE_PROCESS, SWOOLE_SOCK_TCP | SWOOLE_SSL);
$key_dir = dirname(dirname(__DIR__)).'/tests/ssl';

$port2 = $serv->addlistener('0.0.0.0', 9502, SWOOLE_SOCK_TCP);
$port2->on('receive', function($serv, $fd, $from_id, $data){
    echo "port2: ".$data."\n";
});

$serv->set(array(
//	'worker_num' => 4,
	'ssl_cert_file' => __DIR__.'/corpssl.crt',
	'ssl_key_file' => __DIR__.'/corpssl.key',
    'ssl_client_cert_file' => __DIR__.'/ca.crt',
    'ssl_verify_depth' => 10,
));

$serv->on('connect', function (swoole_server $serv, $fd, $from_id){
	echo "[#".posix_getpid()."]\tClient@[$fd:$from_id]: Connect.\n";
    $info = $serv->getClientInfo($fd);
    var_dump($info);
});

$serv->on('receive', function (swoole_server $serv, $fd, $from_id, $data) {
	echo "[#".posix_getpid()."]\tClient[$fd]: $data\n";
	$serv->send($fd, "Swoole: $data\n");
});

$serv->on('close', function ($serv, $fd, $from_id) {
	echo "[#".posix_getpid()."]\tClient@[$fd:$from_id]: Close.\n";
});

$serv->start();

