<?php
$serv = new swoole_server("0.0.0.0", 9501);
$serv->set(array(
	//'tcp_defer_accept' => 5,
	'worker_num' => 1,
    'ipc_mode' => SWOOLE_IPC_MSGQUEUE,
    'message_queue_key' => ftok(__FILE__, 0),
	//'daemonize' => true,
	//'log_file' => '/tmp/swoole.log'
));
$serv->on('timer', function($serv, $interval) {
	echo "onTimer: $interval\n";
});
$serv->on('workerStart', function($serv, $worker_id) {
    global $argv;
    swoole_set_process_name("php {$argv[0]}: worker");
	if($worker_id == 0) $serv->addtimer(1000);
});
$serv->on('connect', function ($serv, $fd, $from_id){
    //echo "[#".posix_getpid()."]\tClient@[$fd:$from_id]: Connect.\n";
});
$serv->on('receive', function (swoole_server $serv, $fd, $from_id, $data) {
    //echo "[#".posix_getpid()."]\tClient[$fd]: $data\n";
    $serv->send($fd, json_encode(array("hello" => '1213', "bat" => "ab")).PHP_EOL);
    //$serv->close($fd);
});
$serv->on('close', function ($serv, $fd, $from_id) {
    //echo "[#".posix_getpid()."]\tClient@[$fd:$from_id]: Close.\n";
});
$serv->start();

