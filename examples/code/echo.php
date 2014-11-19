<?php
$serv = new swoole_server("0.0.0.0", 9502);
$serv->set(array(
	'worker_num' => 1,
	'max_request' => 0,
));

$serv->on('connect', function (swoole_server $serv, $fd, $from_id) {	
	echo "connect\n";;
});

$serv->on('receive', function (swoole_server $serv, $fd, $from_id, $data) {	
	$serv->send($fd, "Swoole: ".$data);
	//$serv->close($fd);
});

//$serv->on('close', function (swoole_server $serv, $fd, $from_id) {	
//	var_dump($serv->connection_info($fd));
//	echo "onClose\n";
//});

$serv->start();
