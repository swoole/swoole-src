<?php
$serv = new swoole_server("0.0.0.0", 9502);
$serv->set(array(
'max_conn' => 1024,
));
$serv->on('workerstart', function($server, $id) {
     global $argv;
     swoole_set_process_name("php {$argv[0]}: worker");
});

//$serv->on('connect', function (swoole_server $serv, $fd, $from_id) {
//	//echo "connect\n";;
//});

$serv->on('receive', function (swoole_server $serv, $fd, $from_id, $data) {	
	$serv->send($fd, "Swoole: ".$data);
	//$serv->close($fd);
});

$serv->on('close', function (swoole_server $serv, $fd, $from_id) {	
	//var_dump($serv->connection_info($fd));
	//echo "onClose\n";
});

$serv->start();
