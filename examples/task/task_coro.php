<?php
$serv = new swoole_server("127.0.0.1", 9501);
$serv->set(array(
    'worker_num' => 1,
    'task_worker_num' => 2,
    //'task_tmpdir' => '/data/task/',
));

$serv->on('Receive', function(swoole_server $serv, $fd, $from_id, $data) {
    $tasks[] = mt_rand(1000, 9999);
    $tasks[] = mt_rand(1000, 9999);
    //等待所有Task结果返回，超时为10s
    var_dump($tasks);
    $results = $serv->taskWaitMulti($tasks, 10.0);
    var_dump($results);
});

$serv->on('Task', function (swoole_server $serv, $task_id, $from_id, $data) {
    echo "onTask: [PID=".posix_getpid()."]: task_id=$task_id, data_len=".strlen($data).".".PHP_EOL;
    return "hello world.[{$data}]";
});

$serv->on('Finish', function (swoole_server $serv, $task_id, $data) {
    echo "Task#$task_id finished, data_len=".strlen($data).PHP_EOL;
});

$serv->start();