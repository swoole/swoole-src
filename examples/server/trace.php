<?php
function test()
{
    test_sleep();
}

function test_sleep()
{
    echo "sleep 5\n";
    sleep(5);
}

$server = new swoole_server('127.0.0.1', 9501);

$server->set([
    'worker_num' => 1,
    'task_worker_num' => 1,
    'request_slowlog_timeout' => 1,
    'request_slowlog_file' => '/tmp/trace.log',
]);

$server->on('Receive', function($serv, $fd, $reactor_id, $data) {
    if (trim($data) == 'task') {
        echo "task\n";
        $serv->task($fd);
        return;
    }
    test();
    $serv->send($fd, "Swoole: $data");
});

$server->on('Task', function (swoole_server $serv, $task_id, $from_id, $data) {
    echo "#{$serv->worker_id}\tonTask: [PID={$serv->worker_pid}]: task_id=$task_id, data_len=".strlen($data).".".PHP_EOL;
    test();
    $serv->send($data, "Swoole: task\n");
});

$server->on('Finish', function (swoole_server $serv, $task_id, $data) {
    echo "Task#$task_id finished, data_len=".strlen($data).PHP_EOL;
});

$server->start();