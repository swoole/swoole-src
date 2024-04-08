<?php
$http = new Swoole\Http\Server("0.0.0.0", 9503);
$http->set([
    'worker_num' => 4,
//    'task_worker_num' => 3,
    'enable_coroutine' => false,
//    'trace_flags' => SWOOLE_TRACE_SERVER,
//    'log_level' => SWOOLE_LOG_TRACE,
    'init_arguments' => function () use ($http) {
        $map = new Swoole\Thread\Map;
        return [$map];
    }
]);

$http->on('Request', function ($req, $resp) use ($http) {
//    $resp->end("tid=" . \Swoole\Thread::getId() . ', fd=' . $req->fd);
    $resp->end('hello world');
});

//$http->addProcess(new \Swoole\Process(function () {
//    echo "user process, id=" . \Swoole\Thread::getId();
//    sleep(2000);
//}));

$http->on('Task', function () {
    var_dump(func_get_args());
});

$http->on('WorkerStart', function ($serv, $wid) {
    var_dump(\Swoole\Thread::getArguments());
});

$http->on('WorkerStop', function ($serv, $wid) {
    var_dump('stop: T' . \Swoole\Thread::getId());
});

$http->start();
