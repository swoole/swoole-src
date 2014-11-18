<?php
$serv = new swoole_server("127.0.0.1", 9501);
$serv->set(array(
    'worker_num' => 1,
    'task_worker_num' => 2,
    //'task_tmpdir' => '/data/task/',
));

$serv->on('Receive', function(swoole_server $serv, $fd, $from_id, $data) {
	//AsyncTask
    $data = intval($data);
    for($i=0;$i<$data;$i++) {
        $tid = mt_rand(0,1);
        echo "data:{$i} to task: {$tid} ".PHP_EOL;
        $serv->task($i, $tid);
    }

});
$serv->on('Task', function (swoole_server $serv, $task_id, $from_id, $data) {
    echo "onTask: [PID=".posix_getpid()."]: task_id=$task_id, data_len=".strlen($data).".".PHP_EOL;
    sleep(10);
    //$serv->finish($data);
    echo 'finish'.PHP_EOL;
    return;
});

$serv->on('Finish', function (swoole_server $serv, $task_id, $data) {
    echo "Task#$task_id finished, data_len=".strlen($data).PHP_EOL;
});

$serv->on('Timer', function(swoole_server $serv, $time) {
    echo "{$time} call".PHP_EOL;
    print_r($serv->stats());
});

$serv->on('workerStart', function($serv, $worker_id) {
	global $argv;
    if($worker_id >= $serv->setting['worker_num']) {
        swoole_set_process_name("php {$argv[0]}: task_worker");
    } else {
        $serv->addtimer(5000);
        swoole_set_process_name("php {$argv[0]}: worker");
    }

});
$serv->start();
