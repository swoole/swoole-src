<?php
$serv = new swoole_server("127.0.0.1", 9501);
$serv->set(array(
    'worker_num' => 2,
    'task_worker_num' => 2,
));
$serv->on('Receive', function(swoole_server $serv, $fd, $from_id, $data) {
	//AsyncTask
    $data = trim($data);
    if($data == 'async')
    {
        $task_id = $serv->task("Async". $data);
        echo "Dispath AsyncTask: id=$task_id\n";
    }
    //Sync Task
	else
    {
        $res = $serv->taskwait("Task". $data);
        echo "Dispath SyncTask: $res\n";
        $serv->send($fd, $res);
    }
});
$serv->on('Task', function (swoole_server $serv, $task_id, $from_id, $data) {
    echo "AsyncTask[PID=".posix_getpid()."]: task_id=$task_id.".PHP_EOL;
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
    echo "AsyncTask[$task_id] Finish: $data".PHP_EOL;
});

$serv->on('workerStart', function($serv, $id) {
	swoole_set_process_name('Swoole: event worker');
});
$serv->start();

