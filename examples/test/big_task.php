<?php
$serv = new swoole_server("127.0.0.1", 9501);
$serv->set(['worker_num' => 1, 'task_worker_num' => 1, 'task_tmpdir' => __DIR__.'/task/']);

$serv->on('connect', function (swoole_server $serv, $fd){
    echo "Client:Connect.\n";
    $data = str_repeat("A", 800000);
    $serv->task($data);
});

$serv->on('receive', function ($serv, $fd, $from_id, $data) {
    //echo "recv n=".strlen($data)."\n";
    //$serv->send($fd, 'Swoole: hello');
});

$serv->on('close', function ($serv, $fd) {
    echo "Client: Close.\n";
});

$serv->on('task', function ($serv, $task_id, $from_id, $data) {
    echo "task length=".strlen($data)."\n";
});

$serv->on('finish', function ($serv, $task_id, $data) {
    //echo "Client: Close.\n";
});

$serv->start();
