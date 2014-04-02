<?php
$serv = new swoole_server("127.0.0.1", 9501);
$serv->set(array(
	'package_eof' => "\r\n\r\n", 
	'open_eof_check' => true,
	'package_max_length' => 1024*1024*2, //2M
));
$serv->on('connect', function ($serv, $fd){
    echo "[#".posix_getpid()."]\tClient:Connect.\n";
});
$serv->on('receive', function ($serv, $fd, $from_id, $data) {
	$req = unserialize(trim($data));
	echo $req['name']."\n";
});
$serv->on('close', function ($serv, $fd) {
    echo "[#".posix_getpid()."]\tClient: Close.\n";
});
$serv->start();
