<?php
$http = new Swoole\Http\Server("0.0.0.0", 9503);
$http->set([
    'worker_num' => 2,
//    'task_worker_num' => 3,
    'enable_coroutine' => false,
    'init_arguments' => function () use ($http) {
        $map = new Swoole\Thread\Map;
        return [$map];
    }
]);

$http->on('Request', function ($req, $resp) use ($http) {
    $resp->end("tid=" . \Swoole\Thread::getId() . ', fd=' . $req->fd);
});

$http->addProcess(new \Swoole\Process(function () {
    echo "user process, id=" . \Swoole\Thread::getId();
    sleep(2);
}));

$http->on('Task', function () {
    var_dump(func_get_args());
});

$http->on('WorkerStart', function ($serv, $wid) {
    var_dump(\Swoole\Thread::getArguments());
});

$http->start();
