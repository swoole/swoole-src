<?php
$serv = new swoole_server("0.0.0.0", 9501, SWOOLE_BASE, SWOOLE_SOCK_TCP | SWOOLE_SSL);
// $serv = new swoole_server("0.0.0.0", 9501, SWOOLE_PROCESS, SWOOLE_SOCK_TCP | SWOOLE_SSL);
$key_dir = dirname(dirname(__DIR__)).'/tests/ssl';

// $port2 = $serv->addlistener('0.0.0.0', 9502, SWOOLE_SOCK_TCP);
// $port2->on('receive', function($serv, $fd, $reactor_id, $data){
//     echo "port2: ".$data."\n";
// });

$serv->set(array(
//	'worker_num' => 4,
	'ssl_cert_file' => __DIR__.'/ca/server-cert.pem',
	'ssl_key_file' => __DIR__.'/ca/server-key.pem',
    'ssl_verify_peer' => true,
    'ssl_allow_self_signed' => true,
    'ssl_client_cert_file' => __DIR__.'/ca/ca-cert.pem',
    'ssl_verify_depth' => 10,
));

$serv->on('connect', function (swoole_server $serv, $fd, $reactor_id){
	echo "[#".posix_getpid()."]\tClient@[$fd:$reactor_id]: Connect.\n";
    $info = $serv->getClientInfo($fd);
    var_dump($info);
});

$serv->on('receive', function (swoole_server $serv, $fd, $reactor_id, $data) {
	echo "[#".posix_getpid()."]\tClient[$fd]: $data\n";
	$serv->send($fd, "Swoole: $data\n");
});

$serv->on('close', function ($serv, $fd, $reactor_id) {
	echo "[#".posix_getpid()."]\tClient@[$fd:$reactor_id]: Close.\n";
});

$serv->start();
