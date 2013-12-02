<?php
/*
argv0  server host
argv1  server port
argv2  server mode SWOOLE_BASE or SWOOLE_THREAD or SWOOLE_PROCESS
argv3  sock_type  SWOOLE_SOCK_TCP or SWOOLE_SOCK_TCP6 or SWOOLE_SOCK_UDP or SWOOLE_SOCK_UDP6
*/
$serv = swoole_server_create("127.0.0.1", 9502, SWOOLE_PROCESS, SWOOLE_SOCK_UDP);

swoole_server_set($serv, array(
    'timeout' => 2.5,  //select and epoll_wait timeout. 
    'worker_num' => 8,    //worker process num
    'max_request' => 5000,
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
    echo "Server:start\n";
}

function my_onShutdown($serv)
{
    echo "Server:onShutdown\n";
}

function my_onTimer($serv, $interval)
{
    //echo "Server:Timer Call.Interval=$interval \n";
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
	//var_dump(swoole_connection_info($serv, $fd, $from_id));
    echo "Client:Data. fd=$fd|from_id=$from_id|data=$data\n";
	if (trim ( $data ) == "reload") 
	{
		swoole_server_reload ( $serv );
	} 
	else 
	{
		swoole_server_send ( $serv, $fd, 'Swoole: ' . $data, $from_id);
	}
	//swoole_server_send($serv, $other_fd, "Server: $data", $other_from_id);	
}

swoole_server_handler($serv, 'onStart', 'my_onStart');
swoole_server_handler($serv, 'onReceive', 'my_onReceive');
swoole_server_handler($serv, 'onShutdown', 'my_onShutdown');
swoole_server_handler($serv, 'onTimer', 'my_onTimer');
swoole_server_handler($serv, 'onWorkerStart', 'my_onWorkerStart');
swoole_server_handler($serv, 'onWorkerStop', 'my_onWorkerStop');
//swoole_server_handler($serv, 'onMasterConnect', 'my_onMasterConnect');
//swoole_server_handler($serv, 'onMasterClose', 'my_onMasterClose');

//swoole_server_addtimer($serv, 2);
#swoole_server_addtimer($serv, 10);
swoole_server_start($serv);

