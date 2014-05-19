<?php
$serv = new swoole_server("127.0.0.1", 9501);
$serv->set(array(
    'worker_num' => 1,
    'task_worker_num' => 1,
));
$serv->on('Receive', function(swoole_server $serv, $fd, $from_id, $data) {
	//AsyncTask
    //$data = trim($data);
    $data = str_repeat('A', 8192*100);
    //if($data == 'async')
    if (false)
    {
        $task_id = $serv->task($data);
        echo "Dispath AsyncTask: id=$task_id\n";
    }
    //Sync Task
	else
    {
        $res = $serv->taskwait($data);
        echo "Dispath SyncTask: data_len=".strlen($res).PHP_EOL;       
    }
    $serv->send($fd, "OK\n");
});
$serv->on('Task', function (swoole_server $serv, $task_id, $from_id, $data) {

    echo "AsyncTask[PID=".posix_getpid()."]: task_id=$task_id, data_len=".strlen($data).".".PHP_EOL;
    $serv->finish($data);
    return;
    
    $start_fd = 0;
	while(true)
	{
		$conn_list = swoole_connection_list($serv, $start_fd, 10);
		if($conn_list===false)
		{
			break;
		}
		$start_fd = $conn_list[count($conn_list)-1];
		foreach($conn_list as $fd)
		{
			$serv->send($fd, "AsyncTask: hello\n");
		}
	}
    $serv->finish("Task:[$data] -> OK\n");
});
$serv->on('Finish', function (swoole_server $serv, $task_id, $data) {
    echo "AsyncTask[$task_id] Finish: data_len=".strlen($data).PHP_EOL;
});

$serv->on('workerStart', function($serv, $worker_id) {
	global $argv;
    if($worker_id >= $serv->setting['worker_num']) {
        swoole_set_process_name("php {$argv[0]}: task_worker");
    } else {
        swoole_set_process_name("php {$argv[0]}: worker");
    }
});
$serv->start();

