<?php
$serv = new swoole_server("0.0.0.0", 9501, SWOOLE_BASE);
//$serv = new swoole_server("0.0.0.0", 9501);
$serv->set(array(
    'worker_num' => 2,
    'task_worker_num' => 2,
));

$serv->on('pipeMessage', function($serv, $src_worker_id, $data) {
	echo "#{$serv->worker_id} message from #$src_worker_id: $data\n";
});

$serv->on('task', function (swoole_server $serv, $task_id, $from_id, $data){
    echo "#{$serv->worker_id} NewTask: $data\n";
    $serv->sendMessage($data, 0);
	//$serv->send($fd, str_repeat('B', 1024*rand(40, 60)).rand(10000, 99999)."\n");
});

$serv->on('finish', function ($serv, $fd, $from_id){
	
});

$serv->on('receive', function (swoole_server $serv, $fd, $from_id, $data) {
    $cmd = trim($data);
    if($cmd == 'totask')
    {
        $serv->sendMessage("hello task process", 2);
    }
    elseif($cmd == 'toworker')
    {
        $worker_id = 1 - $serv->worker_id;
        $serv->sendMessage("hello worker", $worker_id);
    }
    elseif($cmd == 'task2worker')
    {
        $serv->task('hello worker from task.');
    }
    else
    {
        echo "#{$serv->worker_id} Recv: $data\n";
    }
});

$serv->on('close', function ($serv, $fd, $from_id) {
	//echo "[#".posix_getpid()."]\tClient@[$fd:$from_id]: Close.\n";
});

$serv->start();

