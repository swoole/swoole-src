<?php
class MyServer extends swoole_server
{
	function onWorkerStop($worker_id)
	{
		echo "WorkerStart[$worker_id]|pid=".posix_getpid().".\n";
	}
}
$serv = new MyServer("127.0.0.1", 9501, SWOOLE_BASE);

$serv->set(array(
    'timeout' => 2,  //select and epoll_wait timeout.
    'poll_thread_num' => 4, //reactor thread num
    'writer_num' => 4,     //writer thread num
    'worker_num' => 4,    //worker process num
    'backlog' => 128,   //listen backlog
    'max_request' => 5000,
    'max_conn' => 10000,
    'dispatch_mode' => 2,
//    'daemonize' => 1,  //转为后台守护进程运行
	//'open_cpu_affinity' => 1,
    //'data_eof' => "\r\n\r\n",
    //'open_eof_check' => 1,
    //'open_tcp_keepalive' => 1,
    //'log_file' => '/tmp/swoole.log', //swoole error log
));

function my_onStart($serv)
{
    echo "Server: start.Swoole version is [".SWOOLE_VERSION."]\n";
}

function my_onShutdown($serv)
{
    echo "Server: onShutdown\n";
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
	swoole_server_send($serv, $fd, 'Swoole: '.$data, $from_id);
}

function my_onTimer($serv, $interval)
{
	echo "Timer Call.Interval={$interval}\n";
}

$serv->handler('onStart', 'my_onStart');
$serv->handler('onConnect', 'my_onConnect');
$serv->handler('onReceive', 'my_onReceive');
$serv->handler('onClose', 'my_onClose');
$serv->handler('onShutdown', 'my_onShutdown');
$serv->handler('onTimer', 'my_onTimer');
$serv->handler('onWorkerStart', 'my_onWorkerStart');
$serv->addtimer(2);
$serv->start();

