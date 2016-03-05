<?php
$serv = new swoole_server("127.0.0.1", 9501,SWOOLE_BASE);

$serv->set(array(
    //'worker_num' => 1,
    'task_worker_num' => 1,
//    'task_ipc_mode' => 3,
//    'message_queue_key' => 0x70001001,
    //'task_tmpdir' => '/data/task/',
));

$serv->on('Receive', function(swoole_server $serv, $fd, $from_id, $data) {
	//AsyncTask
    $data = trim($data);
    //$data = str_repeat('A', 8192*100);
//    if ($data == 'async')
    if(false)
//    if (true)
    {
        $task_id = $serv->task($data, 0);
        $serv->send($fd, "Dispath AsyncTask: id=$task_id\n");
    }
    //Sync Task
	else
    {
        $res = $serv->taskwait($data, 10);
        echo "Dispath SyncTask: result=".$res.PHP_EOL;       
    }
    //$serv->send($fd, "OK\n");
});
$serv->on('Task', function (swoole_server $serv, $task_id, $from_id, $data) {
    echo "#{$serv->worker_id}\tonTask: [PID={$serv->worker_pid}]: task_id=$task_id, data_len=".strlen($data).".".PHP_EOL;
    $serv->finish($data);
//    return $data;
});

$serv->on('Finish', function (swoole_server $serv, $task_id, $data) {
    echo "Task#$task_id finished, data_len=".strlen($data).PHP_EOL;
});

$serv->on('workerStart', function($serv, $worker_id) {
	global $argv;
    if($worker_id >= $serv->setting['worker_num']) {
        swoole_set_process_name("php {$argv[0]}: task_worker");
    } else {
        swoole_set_process_name("php {$argv[0]}: worker");
    }
});

$serv->start();
