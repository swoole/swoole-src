<?php
$serv = new swoole_server("0.0.0.0", 9501);

$serv->set([
    'worker_num' => 4,
    'reload_async' => true,
    'max_wait_time' => 5,
    'task_worker_num' => 2,
]);

$serv->on('WorkerStart', function ($serv, $wid) {
    echo "Worker#$wid is started\n";
    if ($serv->taskworker) {
        return;
    }
    swoole_event::add(STDIN, function () use ($wid) {
        $data = fread(STDIN, 8192);
        if ($data) {
            echo "#{$wid}: $data";
        }
    });
});

$serv->on('receive', function (swoole_server $serv, $fd, $reactor_id, $data) {
	echo "[#".$serv->worker_id."]\tClient[$fd]: $data\n";
});

$serv->on('Task', function (swoole_server $serv, $task_id, $from_id, $data) {
    //echo "#{$serv->worker_id}\tonTask: [PID={$serv->worker_pid}]: task_id=$task_id, data_len=".strlen($data).".".PHP_EOL;
//    $serv->finish($data);
    return $data;
});

$serv->on('Finish', function (swoole_server $serv, $task_id, $data) {
    echo "Task#$task_id finished, data_len=".strlen($data).PHP_EOL;
});

$serv->on('WorkerStop', function ($serv, $wid) {
    //sleep($wid + 1);
});

$serv->on('WorkerExit', function ($serv, $wid) {
    echo "WorkerExit, PID=".posix_getpid()."\t$wid\n";
    swoole_event::del(STDIN);
});

$serv->start();
