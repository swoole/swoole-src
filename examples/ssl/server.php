<?php
require __DIR__ . '/certs.php';
$serv = new Swoole\Server("0.0.0.0", 9501, SWOOLE_BASE, SWOOLE_SOCK_TCP | SWOOLE_SSL);
// $serv = new Swoole\Server("0.0.0.0", 9501, SWOOLE_PROCESS, SWOOLE_SOCK_TCP | SWOOLE_SSL);

// $port2 = $serv->addlistener('0.0.0.0', 9502, SWOOLE_SOCK_TCP);
// $port2->on('receive', function($serv, $fd, $reactor_id, $data){
//     echo "port2: ".$data."\n";
// });

$serv->set(array(
//	'worker_num' => 4,
	'ssl_cert_file' => SSL_CERT_DIR . 'server-cert.pem',
	'ssl_key_file' => SSL_CERT_DIR . 'server-key.pem',
    'ssl_verify_peer' => true,
    'ssl_allow_self_signed' => true,
    'ssl_client_cert_file' => SSL_CERT_DIR . 'ca-cert.pem',
    'ssl_verify_depth' => 10,
));

$serv->on('connect', function (Swoole\Server $serv, $fd, $reactor_id){
	echo "[#".posix_getpid()."]\tClient@[$fd:$reactor_id]: Connect.\n";
    $info = $serv->getClientInfo($fd);
    var_dump($info);
});

$serv->on('receive', function (Swoole\Server $serv, $fd, $reactor_id, $data) {
	echo "[#".posix_getpid()."]\tClient[$fd]: $data\n";
	$serv->send($fd, "Swoole: $data\n");
});

$serv->on('close', function ($serv, $fd, $reactor_id) {
	echo "[#".posix_getpid()."]\tClient@[$fd:$reactor_id]: Close.\n";
});

$serv->start();
