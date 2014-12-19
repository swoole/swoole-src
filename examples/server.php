<?php
class G
{
	static $serv;
}

$config = array(
    'worker_num' => 1,
    //'open_eof_check' => true,
    //'package_eof' => "\r\n",
    //'ipc_mode' => 2,
    'task_worker_num' => 1,
    //'task_ipc_mode' => 1,
    //'dispatch_mode' => 1,
    //'log_file' => '/tmp/swoole.log',
    //'heartbeat_check_interval' => 10,
);

if (isset($argv[1]) and $argv[1] == 'daemon') {
	$config['daemonize'] = true;
} else {
	$config['daemonize'] = false;
}

$serv = new swoole_server("0.0.0.0", 9501);
$serv->addlistener('0.0.0.0', 9502, SWOOLE_SOCK_UDP);

$process1 = new swoole_process("my_process1", false, false);
//$serv->addprocess($process1);

$serv->set($config);
/**
 * 保存数据到对象属性，在任意位置均可访问
 */
$serv->config = $config;
/**
 * 使用类的静态属性，可以直接访问
 */
G::$serv = $serv;

function my_process1($process)
{
	global $argv;
	var_dump($process);
	swoole_set_process_name("php {$argv[0]}: my_process1");
	sleep(1000);
}

function my_onStart(swoole_server $serv)
{
    global $argv;
    swoole_set_process_name("php {$argv[0]}: master");
    echo "MasterPid={$serv->master_pid}|Manager_pid={$serv->manager_pid}\n";
    echo "Server: start.Swoole version is [".SWOOLE_VERSION."]\n";
}

function my_log($msg)
{
	global $serv;
    echo "#".$serv->worker_pid."\t".$msg.PHP_EOL;
}

function forkChildInWorker() {
	global $serv;
	echo "on worker start\n";
	$process = new swoole_process( function (swoole_process $worker) {
// 		$serv = new swoole_server( "0.0.0.0", 9503 );
// 		$serv->set(array(
// 				'worker_num' => 1 
// 		));
// 		$serv->on ( 'receive', function (swoole_server $serv, $fd, $from_id, $data) {
// 			$serv->send ( $fd, "Swoole: " . $data );
// 			$serv->close ( $fd );
// 		});
// 		$serv->start ();
// 		swoole_event_add ($worker->pipe, function ($pipe) use ($worker) {
// 			echo $worker->read()."\n";
// 		});
// 		swoole_timer_add (1000, function ($interval) use ($worker) {
// 			echo "#{$worker->pid} child process timer $interval\n"; // 如果worker中没有定时器，则会输出 process timer xxx
// 		});
	});
	$pid = $process->start();
	echo "Fork child process success. pid={$pid}\n";
	//保存子进程对象，这里如果不保存，那对象会被销毁，管道也会被关闭
	$serv->childprocess = $process;
}

function processRename($serv, $worker_id) {
	
	global $argv;
	if($worker_id >= $serv->setting['worker_num'])
	{
		swoole_set_process_name("php {$argv[0]}: task");
	}
	else
	{
		swoole_set_process_name("php {$argv[0]}: worker");
	}
	echo "WorkerStart: MasterPid={$serv->master_pid}|Manager_pid={$serv->manager_pid}";
	echo "|WorkerId={$serv->worker_id}|WorkerPid={$serv->worker_pid}\n";
}

function setTimerInWorker(swoole_server $serv, $worker_id) {
	
	if ($worker_id == 0) {
		echo "Start: ".microtime(true)."\n";
		$serv->addtimer(3000);
		$serv->addtimer(7000);
		//var_dump($serv->gettimer());
	}
	$serv->after(2000, function(){
		echo "Timeout: ".microtime(true)."\n";
	});
	$serv->after(5000, function(){
		echo "Timeout: ".microtime(true)."\n";
		global $serv;
		$serv->deltimer(3000);
	});
}

function my_onShutdown($serv)
{
    echo "Server: onShutdown\n";
}

function my_onTimer($serv, $interval)
{
	//echo "Timer#$interval: ".microtime(true)."\n";
}

function my_onClose($serv, $fd, $from_id)
{
    my_log("Worker#{$serv->worker_pid} Client[$fd@$from_id]: fd=$fd is closed");
}

function my_onConnect($serv, $fd, $from_id)
{
    //throw new Exception("hello world");
    echo "Worker#{$serv->worker_pid} Client[$fd@$from_id]: Connect.\n";
}

function my_onWorkerStart($serv, $worker_id)
{
	//processRename($serv, $worker_id);
	//forkChildInWorker();
	setTimerInWorker($serv, $worker_id);
}

function my_onWorkerStop($serv, $worker_id)
{
    echo "WorkerStop[$worker_id]|pid=".$serv->worker_pid.".\n";
}

function my_onReceive(swoole_server $serv, $fd, $from_id, $data)
{
    my_log("Worker#{$serv->worker_pid} Client[$fd@$from_id]: received: $data");
    $cmd = trim($data);
    if($cmd == "reload")
    {
        $serv->reload($serv);
    }
    elseif($cmd == "task")
    {
        $task_id = $serv->task("task-".$fd);
        echo "Dispath AsyncTask: id=$task_id\n";
    }
    elseif($cmd == "taskwait")
    {
        $result = $serv->taskwait("taskwait");
        if ($result) {
        	$serv->send($fd, "taskwaitok");
        }
        echo "SyncTask: result=$result\n";
    }
    elseif ($cmd == "hellotask")
    {
        $serv->task("hellotask");
    }
    elseif($cmd == "close")
    {
        $serv->send($fd, "close connection\n");
        $result = $serv->close($fd);
    }
    elseif($cmd == "info")
    {
        $info = $serv->connection_info($fd);
        $serv->send($fd, 'Info: '.var_export($info, true).PHP_EOL);
    }
    elseif($cmd == "stats")
    {
        $serv_stats = $serv->stats();
        $serv->send($fd, 'Stats: '.var_export($serv_stats, true).PHP_EOL);
    }
    elseif($cmd == "broadcast")
    {
        broadcast($serv, $fd, "hello from $fd\n");
    }
    //这里故意调用一个不存在的函数
    elseif($cmd == "error")
    {
        hello_no_exists();
    }
    //关闭fd
    elseif(substr($cmd, 0, 5) == "close")
    {
        $close_fd = substr($cmd, 6);
        $serv->close($close_fd);
    }
    elseif($cmd == "shutdown")
    {
        $serv->shutdown();
    }
    else
    {
        $ret = $serv->send($fd, 'Swoole: '.$data, $from_id);
        //var_dump($ret);
        //$serv->close($fd);
    }
    //echo "Client:Data. fd=$fd|from_id=$from_id|data=$data";
//    $serv->after(
//        800, function () {
//            echo "hello";
//        }
//    );
    //swoole_server_send($serv, $other_fd, "Server: $data", $other_from_id);
}

function my_onTask(swoole_server $serv, $task_id, $from_id, $data)
{
    //swoole_timer_after(1000, "test");
    var_dump($data);
    $fd = str_replace('task-', '', $data);
    $serv->send($fd, str_repeat('A', 8192*2));
    $serv->send($fd, str_repeat('B', 8192*2));
    $serv->send($fd, str_repeat('C', 8192*2));
    $serv->send($fd, str_repeat('D', 8192*2));
    return;
    
    if ($data == "hellotask")
    {
        broadcast($serv, 0, "hellotask");
    }
    else
    {
        echo "AsyncTask[PID=".$serv->worker_pid."]: task_id=$task_id.".PHP_EOL;
        //eg: test-18
        return $data;
    }
}

function my_onFinish(swoole_server $serv, $task_id, $data)
{
	list($str, $fd) = explode('-', $data);
	$serv->send($fd, 'taskok');
	var_dump($str, $fd);
    echo "AsyncTask Finish: result={$data}. PID=".$serv->worker_pid.PHP_EOL;
}

function my_onWorkerError(swoole_server $serv, $worker_id, $worker_pid, $exit_code)
{
    echo "worker abnormal exit. WorkerId=$worker_id|Pid=$worker_pid|ExitCode=$exit_code\n";
}

function broadcast(swoole_server $serv, $fd = 0, $data = "hello")
{
    $start_fd = 0;
    echo "broadcast\n";
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
            $ret1 = $serv->send($conn, $data);
            //var_dump($ret1);
            //$ret2 = $serv->close($conn);
            //var_dump($ret2);
        }
    }
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
$serv->on('WorkerError', 'my_onWorkerError');
$serv->on('ManagerStart', function($serv) {
    global $argv;
    swoole_set_process_name("php {$argv[0]}: manager");
});
$serv->start();

