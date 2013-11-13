<?php
/*
argv0  server host
argv1  server port
argv2  server mode SWOOLE_BASE or SWOOLE_THREAD or SWOOLE_PROCESS
argv3  sock_type  SWOOLE_SOCK_TCP or SWOOLE_SOCK_TCP6 or SWOOLE_SOCK_UDP or SWOOLE_SOCK_UDP6
*/
$serv = swoole_server_create("127.0.0.1", 9501, SWOOLE_BASE);
swoole_server_set($serv, array(
    'timeout' => 2,  //select and epoll_wait timeout.
    'poll_thread_num' => 4, //reactor thread num
    'writer_num' => 4,     //writer thread num
    'worker_num' => 4,    //worker process num
    'backlog' => 128,   //listen backlog
    'max_request' => 5000,
    'max_conn' => 100000,
    'dispatch_mode' => 2,
//    'daemonize' => 1,  //转为后台守护进程运行
	'open_cpu_affinity' => 1,
    //'data_eof' => "\r\n\r\n",
    //'open_eof_check' => 1,
    //'open_tcp_keepalive' => 1,
    //'log_file' => '/tmp/swoole.log', //swoole error log
));

/*
argv0  server resource
argv1  listen host
argv2  listen port
argv3  sock_type  SWOOLE_SOCK_TCP or SWOOLE_SOCK_TCP6 or SWOOLE_SOCK_UDP or SWOOLE_SOCK_UDP6
*/
//swoole_server_addlisten($serv, "127.0.0.1", 9500, SWOOLE_SOCK_UDP);
function my_onStart($serv)
{
	echo "MasterPid={$serv->master_pid}|Manager_pid={$serv->manager_pid}\n";
    echo "Server: start.Swoole version is [".SWOOLE_VERSION."]\n";
}

function my_onShutdown($serv)
{
    echo "Server: onShutdown\n";
}

function my_onTimer($serv, $interval)
{
    //echo "Server:Timer Call.Interval=$interval \n";
}

function my_onClose($serv, $fd, $from_id)
{
///	echo "Client:Close.\n";
}

function my_onConnect($serv, $fd, $from_id)
{
///	echo "Client:Connect.\n";
}

function my_onWorkerStart($serv, $worker_id)
{
	echo "WorkerStart[$worker_id]|pid=".posix_getpid().".\n";
}

function my_onWorkerStop($serv, $worker_id)
{
	echo "WorkerStop[$worker_id]|pid=".posix_getpid().".\n";
}

function my_onReceive($serv, $fd, $from_id, $data)
{
    //echo "Client:Data. fd=$fd|from_id=$from_id|data=$data";
    //echo "WorkerPid=".posix_getpid()."\n";
    swoole_server_send($serv, $fd, 'Swoole: '.$data, $from_id);
    /*
    if(trim($data) == "reload") 
    {
		swoole_server_reload($serv);
	} 
	else 
	{
		swoole_server_send($serv, $fd, 'Swoole: '.$data, $from_id);
	}
	*/
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
 function my_onMasterClose($serv,$fd,$from_id)
{
    //echo "Client:Close.PID=".posix_getpid().PHP_EOL;
}

function my_onMasterConnect($serv,$fd,$from_id)
{
    //echo "Client:Connect.PID=".posix_getpid().PHP_EOL;
}

swoole_server_handler($serv, 'onStart', 'my_onStart');
swoole_server_handler($serv, 'onConnect', 'my_onConnect');
swoole_server_handler($serv, 'onReceive', 'my_onReceive');
swoole_server_handler($serv, 'onClose', 'my_onClose');
swoole_server_handler($serv, 'onShutdown', 'my_onShutdown');
swoole_server_handler($serv, 'onTimer', 'my_onTimer');
swoole_server_handler($serv, 'onWorkerStart', 'my_onWorkerStart');
swoole_server_handler($serv, 'onWorkerStop', 'my_onWorkerStop');
//swoole_server_handler($serv, 'onMasterConnect', 'my_onMasterConnect');
//swoole_server_handler($serv, 'onMasterClose', 'my_onMasterClose');

//swoole_server_addtimer($serv, 2);
#swoole_server_addtimer($serv, 10);
swoole_server_start($serv);

