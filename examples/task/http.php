<?php
$serv = new swoole_http_server("127.0.0.1", 9501);
$serv->set(array(
    'worker_num' => 1,
    'task_worker_num' => 1,
//    'task_ipc_mode' => 3,
//    'message_queue_key' => 0x70001001,
    //'task_tmpdir' => '/data/task/',
));

$serv->on('Request', function ($req, $resp)
{
    $data = str_repeat('A', 8192 * 10);
    global $serv;

    $serv->task(array($data, 1000), -1, function ($serv, $task_id, $data) use ($resp)
    {
        $resp->end("Task#$task_id finished." . PHP_EOL);
    });

});
$serv->on('Task', function (swoole_server $serv, $task_id, $from_id, $data) {
    //echo "#{$serv->worker_id}\tonTask: [PID={$serv->worker_pid}]: task_id=$task_id, data_len=".strlen($data).".".PHP_EOL;
//    $serv->finish($data);
    return $data;
});

$serv->on('Finish', function (swoole_server $serv, $task_id, $data) {
    echo "Task#$task_id finished, data_len=".strlen($data).PHP_EOL;
});

$serv->on('workerStart', function($serv, $worker_id) {
	global $argv;
    if ($serv->taskworker)
    {
        swoole_set_process_name("php {$argv[0]}: task_worker");
    }
    else
    {
        swoole_set_process_name("php {$argv[0]}: worker");
    }
});

$serv->on('workerStop', function (swoole_server $serv, $id) {
    echo "stop\n";
    var_dump($id);
});

$serv->start();
