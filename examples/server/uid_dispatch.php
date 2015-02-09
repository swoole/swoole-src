<?php
$serv = new swoole_server("0.0.0.0", 9501);
$serv->fdlist = [];
$serv->set(array(
		//'tcp_defer_accept' => 5,
		//'ipc_mode' => 2,
		'worker_num' => 4,
		//'task_worker_num' => 2,
		'dispatch_mode' => 5,   //uid dispatch
		//'max_request' => 1000,
		//'daemonize' => true,
		//'log_file' => '/tmp/swoole.log'
));
$serv->on('timer', function($serv, $interval) {
	echo "onTimer: $interval\n";
});

$serv->on('start', function($serv) {
	//$serv->addtimer(1000);
});

$serv->on('workerStart', function($serv, $worker_id) {
	echo "{$worker_id} start".PHP_EOL;
	//if($worker_id == 0) $serv->addtimer(1000);
});

$serv->on('connect', function ($serv, $fd, $from_id){
	//echo "[#".posix_getpid()."]\tClient@[$fd:$from_id]: Connect.\n";
	echo "{$fd} connect, worker:".$serv->worker_id.PHP_EOL;
});

$serv->on('task', function ($serv, $task_id, $from_id, $data){
});

$serv->on('finish', function ($serv, $fd, $from_id){
	
});

$serv->on('receive', function (swoole_server $serv, $fd, $from_id, $data) {
    $conn = $serv->connection_info($fd);
    print_r($conn);
    echo "worker_id: " . $serv->worker_id . PHP_EOL;
    if (empty($conn['uid'])) {
        $uid = $fd + 1;
        if ($serv->bind($fd, $uid)) {
            $serv->send($fd, "bind {$uid} success");
        }
    } else {
        if (empty($serv->fdlist[$fd])) {
            $serv->fdlist[$fd] = $conn['uid'];
        }
        print_r($serv->fdlist);
        foreach ($serv->fdlist as $_fd => $uid) {
            $serv->send($_fd, "{$fd} say:" . $data . PHP_EOL);
        }
    }
});

$serv->on('close', function ($serv, $fd, $from_id) {
	//echo "[#".posix_getpid()."]\tClient@[$fd:$from_id]: Close.\n";
	unset($serv->fdlist[$fd]);
});

$serv->start();