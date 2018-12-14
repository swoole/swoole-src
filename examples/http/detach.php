<?php
$http = new swoole_http_server("0.0.0.0", 9501);

$http->set(['task_worker_num' => 1, 'worker_num' => 1]);

$http->on('request', function ($req, Swoole\Http\Response $resp) use ($http) {
    $resp->detach();
    $http->task(strval($resp->fd));
});

$http->on('finish', function ()
{
    echo "task finish";
});

$http->on('task', function ($serv, $task_id, $worker_id, $data)
{
    var_dump($data);
    $resp = Swoole\Http\Response::create($data);
    $resp->end("in task");
    echo "async task\n";
});

//$http->on('close', function(){
//    echo "on close\n";
//});


$http->on('workerStart', function ($serv, $id)
{
    //var_dump($serv);
});

$http->start();
