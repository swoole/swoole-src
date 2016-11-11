<?php
class G
{
    static $index = 0;
    static $serv;
    static $config = array(
        //'reactor_num'              => 16,     // 线程数. 一般设置为CPU核数的1-4倍
        'worker_num'               => 1,    // 工作进程数量. 设置为CPU的1-4倍最合理
        'max_request'              => 1000,     // 防止 PHP 内存溢出, 一个工作进程处理 X 次任务后自动重启 (注: 0,不自动重启)
        'max_conn'                 => 10000, // 最大连接数
        'task_worker_num'          => 1,     // 任务工作进程数量
//        'task_ipc_mode'            => 2,     // 设置 Task 进程与 Worker 进程之间通信的方式。
        'task_max_request'         => 0,     // 防止 PHP 内存溢出
        //'task_tmpdir'              => '/tmp',
        //'message_queue_key'        => ftok(SYS_ROOT . 'queue.msg', 1),
        'dispatch_mode'            => 2,
        //'daemonize'                => 1,     // 设置守护进程模式
        'backlog'                  => 128,
        //'log_file'                 => '/data/logs/swoole.log',
        'heartbeat_check_interval' => 10,    // 心跳检测间隔时长(秒)
        'heartbeat_idle_time'      => 20,   // 连接最大允许空闲的时间
        //'open_eof_check'           => 1,
        //'open_eof_split'           => 1,
        //'package_eof'              => "\r\r\n",
        //'open_cpu_affinity'        => 1,
        'socket_buffer_size'         => 1024 * 1024 * 128,
        'buffer_output_size'         => 1024 * 1024 * 2,
        //'enable_delay_receive'       => true,
        //'cpu_affinity_ignore' =>array(0,1)//如果你的网卡2个队列（或者没有多队列那么默认是cpu0来处理中断）,并且绑定了core 0和core 1,那么可以通过这个设置避免swoole的线程或者进程绑定到这2个core，防止cpu0，1被耗光而造成的丢包
    );

    private static $buffers = array();

    /**
     * @param $fd
     * @return swoole_buffer
     */
    static function getBuffer($fd, $create = true)
    {
        if (!isset(self::$buffers[$fd]))
        {
            if (!$create)
            {
                return false;
            }
            self::$buffers[$fd] = new swoole_buffer(1024 * 128);
        }
        return self::$buffers[$fd];
    }
}

if (isset($argv[1]) and $argv[1] == 'daemon') {
	G::$config['daemonize'] = true;
} else {
    G::$config['daemonize'] = false;
}

//$mode = SWOOLE_BASE;
$mode = SWOOLE_PROCESS;

$serv = new swoole_server("0.0.0.0", 9501, $mode, SWOOLE_SOCK_TCP);
$serv->listen('0.0.0.0', 9502, SWOOLE_SOCK_UDP);
$serv->listen('::', 9503, SWOOLE_SOCK_TCP6);
$serv->listen('::', 9504, SWOOLE_SOCK_UDP6);
$process1 = new swoole_process(function ($worker) use ($serv) {
    global $argv;
    swoole_set_process_name("php {$argv[0]}: my_process1");
    swoole_timer_tick(2000, function ($interval) use ($worker, $serv) {
        echo "#{$worker->pid} child process timer $interval\n"; // 如果worker中没有定时器，则会输出 process timer xxx
        foreach ($serv->connections as $conn)
        {
            $serv->send($conn, "heartbeat\n");
        }
    });
    swoole_timer_tick(5000, function () use ($serv)
    {
        $serv->sendMessage("hello event worker", 0);
        $serv->sendMessage("hello task worker", 4);
    });
}, false);

//$serv->addprocess($process1);

$process2 = new swoole_process(function ($worker) use ($serv) {
    global $argv;
    swoole_set_process_name("php {$argv[0]}: my_process2");
    swoole_timer_tick(2000, function ($interval) use ($worker, $serv) {
        echo "#{$worker->pid} child process timer $interval\n"; // 如果worker中没有定时器，则会输出 process timer xxx
    });
}, false);

//$serv->addprocess($process2);
$serv->set(G::$config);
/**
 * 使用类的静态属性，可以直接访问
 */
G::$serv = $serv;

function my_onStart(swoole_server $serv)
{
    global $argv;
    swoole_set_process_name("php {$argv[0]}: master");
    my_log("Server: start.Swoole version is [".SWOOLE_VERSION."]");
    my_log("MasterPid={$serv->master_pid}|Manager_pid={$serv->manager_pid}");
}

function my_log($msg)
{
	global $serv;
    if (empty($serv->worker_pid))
    {
        $serv->worker_pid = posix_getpid();
    }
    echo "#".$serv->worker_pid."\t[".date('H:i:s')."]\t".$msg.PHP_EOL;
}

function forkChildInWorker() {
	global $serv;
	echo "on worker start\n";
	$process = new swoole_process( function (swoole_process $worker) use ($serv) {
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
	});

	$pid = $process->start();
	echo "Fork child process success. pid={$pid}\n";
	//保存子进程对象，这里如果不保存，那对象会被销毁，管道也会被关闭
	$serv->childprocess = $process;
}

function processRename(swoole_server $serv, $worker_id) {
	
	global $argv;
	if ( $serv->taskworker)
	{
		swoole_set_process_name("php {$argv[0]}: task");
	}
	else
	{
		swoole_set_process_name("php {$argv[0]}: worker");
	}
//    if ($worker_id == 0)
//    {
//        var_dump($serv->setting);
//    }
	my_log("WorkerStart: MasterPid={$serv->master_pid}|Manager_pid={$serv->manager_pid}|WorkerId={$serv->worker_id}|WorkerPid={$serv->worker_pid}");
}

function setTimerInWorker(swoole_server $serv, $worker_id) {
	
	if ($worker_id == 0) {
		echo "Start: ".microtime(true)."\n";
		//$serv->addtimer(3000);
//		$serv->addtimer(7000);
		//var_dump($serv->gettimer());
	}
//	$serv->after(2000, function(){
//		echo "Timeout: ".microtime(true)."\n";
//	});
//	$serv->after(5000, function(){
//		echo "Timeout: ".microtime(true)."\n";
//		global $serv;
//		$serv->deltimer(3000);
//	});
}

function my_onShutdown($serv)
{
    echo "Server: onShutdown\n";
}

function my_onClose(swoole_server $serv, $fd, $from_id)
{
    my_log("Client[$fd@$from_id]: fd=$fd is closed");
    $buffer = G::getBuffer($fd);
    if ($buffer)
    {
        $buffer->clear();
    }
    //var_dump($serv->getClientInfo($fd));
}

function my_onConnect(swoole_server $serv, $fd, $from_id)
{
    //throw new Exception("hello world");
//    var_dump($serv->connection_info($fd));
    //var_dump($serv, $fd, $from_id);
//    echo "Worker#{$serv->worker_pid} Client[$fd@$from_id]: Connect.\n";
    //$serv->after(2000, function() use ($serv, $fd) {
    //    $serv->confirm($fd);
    //});
    my_log("Client: Connect --- {$fd}");
}

function timer_show($id)
{
    my_log("Timer#$id");
}
function my_onWorkerStart(swoole_server $serv, $worker_id)
{
	processRename($serv, $worker_id);

    if (!$serv->taskworker)
    {
        swoole_process::signal(SIGUSR2, function($signo){
            echo "SIGNAL: $signo\n";
        });
        $serv->defer(function(){
           echo "defer call\n";
        });
    }
    else
    {
//        swoole_timer_after(2000, function() {
//            echo "after 2 secends.\n";
//        });
//        $serv->tick(1000, function ($id) use ($serv) {
//            if (G::$index > 10) {
//                $serv->after(2500, 'timer_show', 2);
//                G::$index = 0;
//            } else {
//                G::$index++;
//            }
//            timer_show($id);
//        });
    }
	//forkChildInWorker();
//	setTimerInWorker($serv, $worker_id);
}

function my_onWorkerStop($serv, $worker_id)
{
    echo "WorkerStop[$worker_id]|pid=".$serv->worker_pid.".\n";
}

function my_onPacket($serv, $data, $clientInfo)
{
    $serv->sendto($clientInfo['address'], $clientInfo['port'], "Server " . $data);
    var_dump($clientInfo);
}

function my_onReceive(swoole_server $serv, $fd, $from_id, $data)
{
    my_log("Worker#{$serv->worker_pid} Client[$fd@$from_id]: received: $data");
    $cmd = trim($data);
    if($cmd == "reload")
    {
        $serv->reload();
    }
    elseif($cmd == "task")
    {
        $task_id = $serv->task("task ".$fd);
        echo "Dispath AsyncTask: id=$task_id\n";
    }
    elseif ($cmd == "taskclose")
    {
        $serv->task("close " . $fd);
        echo "close the connection in taskworker\n";
    }
    elseif ($cmd == "tasksend")
    {
        $serv->task("send " . $fd);
    }
    elseif ($cmd == "bigtask")
    {
        $serv->task(str_repeat('A', 8192*5));
    }
    elseif($cmd == "taskwait")
    {
        $result = $serv->taskwait("taskwait");
        if ($result) {
        	$serv->send($fd, "taskwaitok");
        }
        echo "SyncTask: result=".var_export($result, true)."\n";
    }
    elseif($cmd == "taskWaitMulti")
    {
        $result = $serv->taskWaitMulti(array(
            str_repeat('A', 8192 * 5),
            str_repeat('B', 8192 * 6),
            str_repeat('C', 8192 * 8)
        ));
        if ($result)
        {
            $resp = "taskWaitMulti ok\n";
            foreach($result as $k => $v)
            {
                $resp .= "result[$k] length=".strlen($v)."\n";
            }
            $serv->send($fd, $resp);
        }
        else
        {
            $serv->send($fd, "taskWaitMulti error\n");
        }
    }
    elseif ($cmd == "hellotask")
    {
        $serv->task("hellotask");
    }
    elseif ($cmd == "taskcallback")
    {
        $serv->task("taskcallback", -1, function (swoole_server $serv, $task_id, $data)
        {
            echo "Task Callback: ";
            var_dump($task_id, $data);
        });
    }
    elseif ($cmd == "sendto")
    {
        $serv->sendto("127.0.0.1", 9999, "hello world");
    }
    elseif($cmd == "close")
    {
        $serv->send($fd, "close connection\n");
        $result = $serv->close($fd);
    }
    elseif($cmd == "info")
    {
        $info = $serv->connection_info(strval($fd), $from_id);
        var_dump($info["remote_ip"]);
        $serv->send($fd, 'Info: '.var_export($info, true).PHP_EOL);
    }
    elseif ($cmd == 'proxy')
    {
        $serv->send(1, "hello world\n");
    }
    elseif ($cmd == 'sleep')
    {
        sleep(10);
    }
    elseif ($cmd == 'foreach')
    {
        foreach($serv->connections as $fd)
        {
            echo "conn : $fd\n";
        }
        return;
    }
    elseif ($cmd == 'tick')
    {
        $serv->tick(2000, function ($id) {
            echo "tick #$id\n";
        });
    }
    elseif ($cmd == 'addtimer')
    {
        $serv->addtimer(3000);
    }
    elseif($cmd == "list")
    {
        $start_fd = 0;
        echo "broadcast\n";
        while(true)
        {
            $conn_list = $serv->connection_list($start_fd, 10);
            if (empty($conn_list))
            {
                echo "iterates finished\n";
                break;
            }
            $start_fd = end($conn_list);
            var_dump($conn_list);
        }
    }
    elseif($cmd == "list2")
    {
        foreach($serv->connections as $con)
        {
            var_dump($serv->connection_info($con));
        }
    }
    elseif($cmd == "stats")
    {
        $serv_stats = $serv->stats();
        $serv->send($fd, 'Stats: '.var_export($serv_stats, true)."\ncount=".count($serv->connections).PHP_EOL);
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
    elseif($cmd == "exit")
    {
        exit("worker php exit.\n");
    }
    elseif ($cmd == 'pause')
    {
        echo "pause receive data. fd={$fd}\n";
        $serv->pause($fd);
    }
    elseif(substr($cmd, 0, 6) == "resume")
    {
        $resume_fd = substr($cmd, 7);
        $serv->resume($resume_fd);
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
    elseif($cmd == "fatalerror")
    {
        require __DIR__.'/php/error.php';
    }
    elseif($cmd == 'sendbuffer')
    {
        $buffer = G::getBuffer($fd);
        $buffer->append("hello\n");
        $serv->send($fd, $buffer);
    }
    elseif($cmd == 'defer')
    {
        $serv->defer(function() use ($fd, $serv) {
            $serv->close($fd);
            $serv->defer(function(){
                echo "deferd\n";
            });
        });
        $serv->send($fd, 'Swoole: '.$data, $from_id);
    }
    else
    {
        $serv->send($fd, 'Swoole: '.$data, $from_id);
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
    if ($data == 'taskwait')
    {
        $fd = str_replace('task-', '', $data);
        $serv->send($fd, "hello world");
        return array("task" => 'wait');
    }
    elseif ($data == 'taskcallback')
    {
        return array("task" => 'callback');
    }
    else
    {
        $cmd = explode(' ', $data);
        if ($cmd[0] == 'send')
        {
            $serv->send($cmd[1], str_repeat('A', 10000)."\n");
        }
        elseif ($cmd[0] == 'close')
        {
            $serv->close($cmd[1]);
        }
        else
        {
            echo "bigtask: length=".strlen($data)."\n";
            return $data;
        }
//        $serv->sendto('127.0.0.1', 9999, "hello world");
        //swoole_timer_after(1000, "test");
//        var_dump($data);
//        $serv->send($fd, str_repeat('A', 8192 * 2));
//        $serv->send($fd, str_repeat('B', 8192 * 2));
//        $serv->send($fd, str_repeat('C', 8192 * 2));
//        $serv->send($fd, str_repeat('D', 8192 * 2));
        return;
    }

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

function my_onWorkerError(swoole_server $serv, $worker_id, $worker_pid, $exit_code, $signo)
{
    echo "worker abnormal exit. WorkerId=$worker_id|Pid=$worker_pid|ExitCode=$exit_code|Signal=$signo\n";
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

$serv->on('PipeMessage', function($serv, $src_worker_id, $msg) {
    my_log("PipeMessage: Src={$src_worker_id},Msg=".trim($msg));
    if ($serv->taskworker)
    {
        $serv->sendMessage("hello user process",
            $src_worker_id);
    }
});

$serv->on('Start', 'my_onStart');
$serv->on('Connect', 'my_onConnect');
$serv->on('Receive', 'my_onReceive');
$serv->on('Packet', 'my_onPacket');
$serv->on('Close', 'my_onClose');
$serv->on('Shutdown', 'my_onShutdown');
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

