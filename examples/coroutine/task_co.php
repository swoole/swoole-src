<?php
$server = new Swoole\Http\Server("127.0.0.1", 9502, SWOOLE_BASE);

$server->set([
    'worker_num' => 1,
    'task_worker_num' => 2,
]);

$server->on('Task', function (swoole_server $serv, $task_id, $worker_id, $data) {
    echo "#{$serv->worker_id}\tonTask: worker_id={$worker_id}, task_id=$task_id\n";
    if ($serv->worker_id == 1) {
        sleep(1);
    }
    return $data;
});

$server->on('Finish', function (swoole_server $serv, $task_id, $data) {
    echo "Task#$task_id finished, data_len=".strlen($data).PHP_EOL;
});

$server->on('Request', function ($request, $response) use ($server)
{
    $result = $server->taskCo(["hello world", ['data' => 1234, 'code' => 200]], 0.5);
    $response->end('Test End, Result: '.var_export($result, true));
});

$server->start();
