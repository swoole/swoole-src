<?php
$serv = new swoole_server("127.0.0.1", 9501);
$serv->set(['worker_num' => 1, 'task_worker_num' => 1]);
$serv->sleep = true;
$serv->count = 500;
$serv->on('connect', function ($serv, $fd){
    //echo "Client:Connect.\n";
    for ($i = 0; $i < $serv->count; $i++) {
        $serv->task(str_repeat("A", 8000));
    }
});

$serv->on('receive', function ($serv, $fd, $from_id, $data) {
//    if ($serv->sleep) {
//        sleep(10);
//        $serv->sleep = false;
//    }

    echo "recv n=".strlen($data)."\n";
    //$serv->send($fd, 'Swoole: hello');
});

$serv->on('close', function ($serv, $fd) {
    //echo "Client: Close.\n";
});

$serv->on('task', function ($serv, $task_id, $from_id, $data) {
    static $count = 0;
    if ($serv->sleep) {
        sleep(10);
        $serv->sleep = false;
    }
    echo "task n=".strlen($data)."\n";
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
