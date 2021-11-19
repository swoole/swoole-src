<?php
$serv = new Swoole\Server("127.0.0.1", 9501, SWOOLE_BASE);

$serv->set(array(
    //'worker_num' => 1,
    'task_worker_num' => 4,
    'task_ipc_mode' => 3,
    'message_queue_key' => 0x70001001,
    'task_tmpdir' => '/data/task/',
));

$serv->on('Receive', function(Swoole\Server $serv, $fd, $reactor_id, $data) {
});

$serv->on('Task', function (Swoole\Server $serv, $task_id, $reactor_id, $data) {
    echo "#{$serv->worker_id}\tonTask: [PID={$serv->worker_pid}]: TASK_ID=$task_id]\n";
    var_dump($data);
});

$serv->on('Finish', function (Swoole\Server $serv, $task_id, $data) {
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
