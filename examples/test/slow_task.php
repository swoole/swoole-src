<?php
$serv = new swoole_server("127.0.0.1", 9501);
$serv->set(['worker_num' => 1, 'task_worker_num' => 1]);
$serv->sleep = true;
$serv->count = 500;
$serv->on('connect', function (swoole_server $serv, $fd){
    echo "Client:Connect.\n";
    $data = str_repeat("A", 8000);
    for ($i = 0; $i < $serv->count; $i++) {
        //$serv->send($fd, $data);
        $serv->task($data);
    }
});

$serv->on('receive', function ($serv, $fd, $from_id, $data) {
//    if ($serv->sleep) {
//        sleep(10);
//        $serv->sleep = false;
//    }

    //echo "recv n=".strlen($data)."\n";
    //$serv->send($fd, 'Swoole: hello');
});

$serv->on('close', function ($serv, $fd) {
    echo "Client: Close.\n";
});

$serv->on('task', function ($serv, $task_id, $from_id, $data) {
    static $count = 0;
    if ($serv->sleep) {
        sleep(10);
        $serv->sleep = false;
    }
    echo "task id=$task_id, len=".strlen($data)."\n";
    $count ++;
    if ($count == $serv->count)
    {
        $serv->sleep = true;
    }
});

$serv->on('finish', function ($serv, $task_id, $data) {
    //echo "Client: Close.\n";
});

$serv->start();
