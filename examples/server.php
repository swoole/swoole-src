<?php
$serv = new swoole_server("0.0.0.0", 9501);
// $serv->addlistener('0.0.0.0', 9502, SWOOLE_SOCK_UDP);
$serv->set(array(
    'worker_num' => 4,
    //'open_eof_check' => true,
    //'package_eof' => "\r\n",
    //'ipc_mode' => 2,
    //'task_worker_num' => 2,
    //'task_ipc_mode' => 1,
    //'dispatch_mode' => 1,
    //'daemonize' => 1,
    //'log_file' => '/tmp/swoole.log',
    //'heartbeat_check_interval' => 10,
));

function my_onStart(swoole_server $serv)
{
    global $argv;
    swoole_set_process_name("php {$argv[0]}: master");
    echo "MasterPid={$serv->master_pid}|Manager_pid={$serv->manager_pid}\n";
    echo "Server: start.Swoole version is [".SWOOLE_VERSION."]\n";
}

function my_log($msg)
{
    echo "#".posix_getpid()."\t".$msg.PHP_EOL;
}

function my_onShutdown($serv)
{
    echo "Server: onShutdown\n";
}

function my_onTimer($serv, $interval)
{
    my_log("Server:Timer Call.Interval=$interval");
}

function my_onClose($serv, $fd, $from_id)
{
    //my_log("Client[$fd@$from_id]: fd=$fd is closed");
}

function my_onConnect($serv, $fd, $from_id)
{
    //throw new Exception("hello world");
    //echo "Client[$fd@$from_id]: Connect.\n";
}

function my_onWorkerStart($serv, $worker_id)
{
    global $argv;
    if($worker_id >= $serv->setting['worker_num']) {
        swoole_set_process_name("php {$argv[0]}: task_worker");
    } else {
        swoole_set_process_name("php {$argv[0]}: worker");
    }
    echo "WorkerStart: MasterPid={$serv->master_pid}|Manager_pid={$serv->manager_pid}";
    echo "|WorkerId={$serv->worker_id}|WorkerPid={$serv->worker_pid}\n";

//     if ($worker_id == 2)
//     {
//     	$serv->addtimer(2000); //500ms
//     	$serv->addtimer(6000); //500ms
//     	var_dump($serv->gettimer());
//     }
}

function my_onWorkerStop($serv, $worker_id)
{
    echo "WorkerStop[$worker_id]|pid=".posix_getpid().".\n";
}

function my_onReceive(swoole_server $serv, $fd, $from_id, $data)
{
    //my_log("received: $data");
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
    elseif($cmd == "taskwait")
    {
        $result = $serv->taskwait("hello world", 2);
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
    //$serv->deltimer(800);
    //swoole_server_send($serv, $other_fd, "Server: $data", $other_from_id);
}

function my_onTask(swoole_server $serv, $task_id, $from_id, $data)
{
    if ($data == "hellotask")
    {
        broadcast($serv, 0, "hellotask");
    }
    else
    {
        echo "AsyncTask[PID=".posix_getpid()."]: task_id=$task_id.".PHP_EOL;
        return "Task OK";
    }
}

function my_onFinish(swoole_server $serv, $task_id, $data)
{
    echo "AsyncTask Finish: result={$data}. PID=".posix_getpid().PHP_EOL;
}

function my_onWorkerError(swoole_server $serv, $worker_id, $worker_pid, $exit_code)
{
    echo "worker abnormal exit. WorkerId=$worker_id|Pid=$worker_pid|ExitCode=$exit_code\n";
}

function broadcast($serv, $fd = 0, $data = "hello")
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
            sleep(5);
            $ret1 = $serv->send($conn, $data);
            var_dump($ret1);
            $ret2 = $serv->close($conn);
            var_dump($ret2);
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

