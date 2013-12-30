<?php
$serv = new swoole_server("127.0.0.1", 9501);
$serv->set(array(
    'worker_num' => 2,
    'task_worker_num' => 2,
//    'daemonize' => 1,
));
$serv->on('Receive', function($serv, $fd, $from_id, $data) {
	
	//AsyncTask
	//$task_id = $serv->task("Async");
	//echo "Dispath AsyncTask: id=$task_id\n";
	
	//Sync Task
	$res = $serv->taskwait("Task". $data);
	echo "Dispath SyncTask: $res\n";
	$serv->send($fd, $res);

});
$serv->on('Task', function ($serv, $task_id, $from_id, $data) {
    echo "AsyncTask[PID=".posix_getpid()."]: task_id=$task_id.".PHP_EOL;
    $serv->finish("$data -> OK");
});
$serv->on('Finish', function ($serv, $data) {
    echo "AsyncTask Finish: $data".PHP_EOL;
}
);
$serv->start();

