<?php
$serv = new swoole_server("127.0.0.1", 9501);
$serv->set(array(
    'worker_num' => 2,
    //'open_eof_check' => true,
    //'package_eof' => "\r\n",
    'task_worker_num' => 2,
	//'dispatch_mode' => 2,
	//'daemonize' => 1,
    //'heartbeat_idle_time' => 5,
    //'heartbeat_check_interval' => 5,
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
// 	echo "Client:Connect.\n";
}


$class = null;
function my_onWorkerStart($serv, $worker_id)
{
    global $argv;
    global $class;
    opcache_reset();
    include "hot_update_class.php";
    $class = new HotUpdate();
    if($worker_id >= $serv->setting['worker_num']) {
        swoole_set_process_name("php {$argv[0]} task worker");
    } else {
        swoole_set_process_name("php {$argv[0]} event worker");
    }
    //echo "WorkerStart|MasterPid={$serv->master_pid}|Manager_pid={$serv->manager_pid}|WorkerId=$worker_id\n";
	//$serv->addtimer(500); //500ms
}

function my_onWorkerStop($serv, $worker_id)
{
	echo "WorkerStop[$worker_id]|pid=".posix_getpid().".\n";
}

function my_onReceive(swoole_server $serv, $fd, $from_id, $data)
{
	$cmd = trim($data);
    if($cmd == "reload") 
    {
		$serv->reload($serv);
	}
	elseif($cmd == "task") 
    {
		$task_id = $serv->task("hello world", 0);
		echo "Dispath AsyncTask: id=$task_id\n";
	}
	elseif($cmd == "info") 
    {
		$info = $serv->connection_info($fd);
		$serv->send($fd, 'Info: '.var_export($info, true).PHP_EOL);
	}
    elseif($cmd == "broadcast")
    {
        $start_fd = 0;
        while(true)
        {
            $conn_list = $serv->connection_list($start_fd, 10);
            if($conn_list === false)
            {
                break;
            }
            $start_fd = end($conn_list);
            foreach($conn_list as $conn)
            {
                if($conn === $fd) continue;
                $serv->send($conn, "hello from $fd\n");
            }
        }
    }
    //这里故意调用一个不存在的函数
    elseif($cmd == "error")
    {
        hello_no_exists();
    }
	elseif($cmd == "shutdown") 
    {
		$serv->shutdown();
	}
	else 
	{
        global $class;
        $data .= $class->getData();
		$serv->send($fd, 'Swoole: '.$data, $from_id);
		//$serv->close($fd);
	}
	//echo "Client:Data. fd=$fd|from_id=$from_id|data=$data";
	//$serv->deltimer(800);
	//swoole_server_send($serv, $other_fd, "Server: $data", $other_from_id);
}

function my_onTask(swoole_server $serv, $task_id, $from_id, $data)
{
    echo "AsyncTask[PID=".posix_getpid()."]: task_id=$task_id.".PHP_EOL;
    $serv->finish("OK");
}

function my_onFinish(swoole_server $serv, $data)
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
$serv->on('WorkerError', function($serv, $worker_id, $worker_pid, $exit_code) {
    echo "worker abnormal exit. WorkerId=$worker_id|Pid=$worker_pid|ExitCode=$exit_code\n";
});
$serv->start();

