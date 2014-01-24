<?php
$serv = new swoole_server("127.0.0.1", 9501);
$serv->set(array(
    'worker_num' => 4,
    //'open_eof_check' => true,
    //'data_eof' => "\n",
    //'task_worker_num' => 2,
	//'dispatch_mode' => 2,
//    'daemonize' => 1,
     //'heartbeat_idle_time' => 30,
     //'heartbeat_check_interval' => 30,
));

function my_onStart($serv)
{
	echo "MasterPid={$serv->master_pid}|Manager_pid={$serv->manager_pid}\n";
    echo "Server: start.Swoole version is [".SWOOLE_VERSION."]\n";
    //$serv->addtimer(1000);
}

function my_onShutdown($serv)
{
    echo "Server: onShutdown\n";
}

function my_onTimer($serv, $interval)
{
    echo "Server:Timer Call.Interval=$interval\n";
}

function my_onClose($serv, $fd, $from_id)
{
	//echo "Client: fd=$fd is closed.\n";
}

function my_onConnect($serv, $fd, $from_id)
{
	//throw new Exception("hello world");
 	echo "Client:Connect.\n";
}

function my_onWorkerStart($serv, $worker_id)
{
    echo "WorkerStart|MasterPid={$serv->master_pid}|Manager_pid={$serv->manager_pid}|WorkerPid=".posix_getpid()."\n";
	//$serv->addtimer(500); //500ms
}

function my_onWorkerStop($serv, $worker_id)
{
	echo "WorkerStop[$worker_id]|pid=".posix_getpid().".\n";
}

function my_onReceive($serv, $fd, $from_id, $data)
{
	$cmd = trim($data);
    if($cmd == "reload") 
    {
		$serv->reload($serv);
	}
	elseif($cmd == "task") 
    {
		$task_id = $serv->task("hello world");
		echo "Dispath AsyncTask: id=$task_id\n";
	}
	elseif($cmd == "info") 
    {
		$info = $serv->connection_info($fd);
		$serv->send($fd, 'Info: '.var_export($info, true).PHP_EOL);
	}
	elseif($cmd == "shutdown") 
    {
		$serv->shutdown();
	}
	else 
	{
		$serv->send($fd, 'Swoole: '.$data, $from_id);
		//$serv->close($fd);
	}
	//echo "Client:Data. fd=$fd|from_id=$from_id|data=$data";
    //echo "WorkerPid=".posix_getpid()."\n";
    //swoole_server_send($serv, $fd, 'Swoole: '.$data, $from_id);
	//$serv->deltimer(800);
	//swoole_server_send($serv, $other_fd, "Server: $data", $other_from_id);
	//swoole_server_close($serv, $fd, $from_id);
	//swoole_server_close($serv, $ohter_fd, $other_from_id);
	
	/*
	 * require swoole-1.5.8+
	var_dump(swoole_connection_info($serv, $fd));
	$start_fd = 0;
	while(true)
	{
		$conn_list = swoole_connection_list($serv, $start_fd, 10);
		if($conn_list===false)
		{
			echo "finish\n";
			break;
		}
		$start_fd = $conn_list[count($conn_list)-1];
		var_dump($conn_list);
	}
	*/
}

function my_onMasterConnect($serv, $fd, $from_id)
{
    //echo "my_onMasterConnect:Close.PID=".posix_getpid().PHP_EOL;
}

function my_onMasterClose($serv,$fd,$from_id)
{
    echo "Client:Close.PID=".posix_getpid().PHP_EOL;
}

function my_onTask($serv, $task_id, $from_id, $data)
{
    echo "AsyncTask[PID=".posix_getpid()."]: task_id=$task_id.".PHP_EOL;
    $serv->finish("OK");
}

function my_onFinish($serv, $data)
{
    echo "AsyncTask Finish:Connect.PID=".posix_getpid().PHP_EOL;
}

$serv->on('Start', 'my_onStart');
$serv->on('Connect', 'my_onConnect');
$serv->on('Receive', 'my_onReceive');
$serv->on('Close', 'my_onClose');
$serv->on('Shutdown', 'my_onShutdown');
$serv->on('Timer', 'my_onTimer');
$serv->on('WorkerStart', 'my_onWorkerStart');
$serv->on('WorkerStop', 'my_onWorkerStop');
$serv->on('Task', 'my_onTask');
$serv->on('Finish', 'my_onFinish');
//$serv->on('MasterConnect', 'my_onMasterConnect');
//$serv->on('MasterClose', 'my_onMasterClose');
$serv->start();

