<?php
$serv = new swoole_server("127.0.0.1", 9501, SWOOLE_BASE);
$serv->set(array(
    'worker_num' => 2,
    'task_worker_num' => 2,
));
$serv->on('Receive', function($serv, $fd, $from_id, $data) {
	//AsyncTask
	$task_id = $serv->task("Async");
	echo "Dispath AsyncTask: id=$task_id\n";
	
	//Sync Task
	//$res = $serv->taskwait("Task". $data);
	//echo "Dispath SyncTask: $res\n";
	//$serv->send($fd, $res);
});
$serv->on('Task', function ($serv, $task_id, $from_id, $data) {
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
    $serv->finish("$data -> OK");
});
$serv->on('Finish', function ($serv, $task_id, $data) {
    echo "AsyncTask[$task_id] Finish: $data".PHP_EOL;
    $serv->send();
}
);

$serv->on('workerStart', function($serv, $id) {
	swoole_set_process_name('Swoole: event worker');
});
$serv->start();

