<?php
$http = new Swoole\Http\Server("0.0.0.0", 9503);
$http->set([
    'worker_num' => 2,
//    'task_worker_num' => 3,
    'enable_coroutine' => false,
]);

$http->on('Request', function ($req, $resp) use ($http) {
    var_dump($http);
});

$http->addProcess(new \Swoole\Process(function () {
    echo "user process";
    sleep(100);
}));

$http->on('Task', function () {
    var_dump(func_get_args());
});

$http->start(function () use ($http) {
    $http->map = new Swoole\Thread\Map();
});
