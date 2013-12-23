<?php
$serv = new swoole_server("127.0.0.1", 9501);
swoole_server_set($serv, array(
    'timeout' => 200,  //select and epoll_wait timeout.
    'worker_num' => 2,    //worker process num
    'max_request' => 5000,
    'max_conn' => 10000,
//    'daemonize' => 1,
	'open_cpu_affinity' => 1,
   //'data_eof' => "\r\n\r\n",
    //'open_eof_check' => 1,
    //'open_tcp_keepalive' => 1,
    //'log_file' => '/tmp/swoole.log', //swoole error log
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
 	//echo "Client:Connect.\n";
}

function my_onWorkerStart($serv, $worker_id)
{
    //sleep(10);
	echo "WorkerStart[$worker_id]|pid=".posix_getpid().".\n";
	//$serv->addtimer(500);
	
	//$serv->addtimer(6000);
}

function my_onWorkerStop($serv, $worker_id)
{
	echo "WorkerStop[$worker_id]|pid=".posix_getpid().".\n";
}

function my_onReceive($serv, $fd, $from_id, $data)
{
    //echo "Client:Data. fd=$fd|from_id=$from_id|data=$data";
    //echo "WorkerPid=".posix_getpid()."\n";
    //swoole_server_send($serv, $fd, 'Swoole: '.$data, $from_id);
	//$serv->deltimer(800);
    if(trim($data) == "reload") 
    {
		$serv->reload($serv);
	}
	elseif(trim($data) == "task") 
    {
		$task_id = $serv->task("hello world");
		echo "Dispath AsyncTask: id=$task_id\n";
	}
	else 
	{
		$serv->send($fd, 'Swoole: '.$data, $from_id);
		$serv->close($fd);
	}
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

