<?php
// Push N tasks to task workers and print server stats periodically.
$serv = new Swoole\Server('127.0.0.1', 9501);
$serv->set([
    'worker_num' => 1,
    'task_worker_num' => 2,
]);
$serv->on('receive', function (Swoole\Server $serv, $fd, $reactor_id, $data) {
    $data = intval($data);
    for ($i = 0; $i < $data; $i++) {
        $tid = mt_rand(0, 1);
        echo "data:{$i} to task: {$tid} " . PHP_EOL;
        $serv->task($i, $tid);
    }
});
$serv->on('task', function (Swoole\Server $serv, $task_id, $reactor_id, $data) {
    echo 'onTask: [PID=' . posix_getpid() . ']: task_id=' . $task_id . ', data_len=' . strlen($data) . '.' . PHP_EOL;
    sleep(10);
    echo 'finish' . PHP_EOL;
});
$serv->on('finish', function (Swoole\Server $serv, $task_id, $data) {
    echo "Task#$task_id finished, data_len=" . strlen($data) . PHP_EOL;
});
$serv->on('workerStart', function ($serv, $worker_id) {
    global $argv;
    if ($worker_id >= $serv->setting['worker_num']) {
        swoole_set_process_name("php {$argv[0]}: task_worker");
    } else {
        Swoole\Timer::tick(5000, function () use ($serv) {
            print_r($serv->stats());
        });
        swoole_set_process_name("php {$argv[0]}: worker");
    }
});
$serv->start();
