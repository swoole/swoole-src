<?php
$serv = new swoole_server("127.0.0.1", 9501);
$serv->on('timer', function($serv, $interval) {
	echo "onTimer: $interval\n";
});
$serv->on('workerStart', function($serv, $worker_id) {
	if($worker_id == 0) $serv->addtimer(300);
});
$serv->on('connect', function ($serv, $fd){
    echo "Client:Connect.\n";
});
$serv->on('receive', function ($serv, $fd, $from_id, $data) {
	$serv->send($fd, 'Swoole: '.$data);
    //$serv->close($fd);
});
$serv->on('close', function ($serv, $fd) {
    echo "Client: Close.\n";
});
$serv->start();
