<?php
$serv = new swoole_server("127.0.0.1", 9501);
$serv->set(array(
    'worker_num' => 1,
    'task_worker_num' => 4,
    //'task_tmpdir' => '/data/task/',
));

$serv->on('Receive', function(swoole_server $serv, $fd, $from_id, $data) {
    $tasks[] = mt_rand(1000, 9999);
    $tasks[] = mt_rand(1000, 9999);
    $tasks[] = mt_rand(1000, 9999);
    $tasks[] = mt_rand(1000, 9999);
    //等待所有Task结果返回，超时为10s
    var_dump($tasks);
    $results = $serv->taskWaitMulti($tasks, 2);
    var_dump($results);
});

$serv->on('Task', function (swoole_server $serv, $task_id, $from_id, $data) {
    echo "onTask: [ID={$serv->worker_id}]: task_id=$task_id, data=$data, data_len=".strlen($data).".".PHP_EOL;
    //测试超时
    if ($serv->worker_id % 4 == 3)
    {
        sleep(3);
    }
    elseif ($serv->worker_id % 4 == 2)
    {
        usleep(1500000);
    }
    elseif ($serv->worker_id % 4 == 1)
    {
        usleep(200000);
    }
    return "hello world.[{$data}]";
});

$serv->on('Finish', function (swoole_server $serv, $task_id, $data) {
    echo "Task#$task_id finished, data_len=".strlen($data).PHP_EOL;
});

$serv->start();