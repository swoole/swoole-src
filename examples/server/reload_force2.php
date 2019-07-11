<?php
$flag = 0;
$serv = new swoole_server('127.0.0.1', 9501);
$serv->set([
    "worker_num" => 4,
    "max_wait_time" => 1
]);
$serv->on("WorkerStart", function (\swoole_server $server, $worker_id) {
    global $flag;
    echo "$worker_id [".$server->worker_pid."] start \n";
});
$serv->on('receive', function ($serv, $fd, $tid, $data) {
    echo "$tid recv $data\n";
    if ($data) {
        sleep(100);
    }
});
$serv->start();