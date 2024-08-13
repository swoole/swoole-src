<?php

use Swoole\Http\Server;

$http = new Server("0.0.0.0", 9503, SWOOLE_THREAD);
$http->set([
    'worker_num' => 2,
    'task_worker_num' => 3,
    'enable_coroutine' => true,
    'hook_flags' => SWOOLE_HOOK_ALL,
//    'trace_flags' => SWOOLE_TRACE_SERVER,
//    'log_level' => SWOOLE_LOG_TRACE,
    'init_arguments' => function () use ($http) {
        $map = new Swoole\Thread\Map;
        return [$map];
    }
]);

$http->on('Request', function ($req, $resp) use ($http) {
//    $resp->end("tid=" . \Swoole\Thread::getId() . ', fd=' . $req->fd);
    if ($req->server['request_uri'] == '/task') {
        $http->task(['code' => uniqid()]);
    } elseif ($req->server['request_uri'] == '/stop') {
        var_dump($http->getWorkerId());
        var_dump($req->get['worker_id']);
        $http->stop($req->get['worker_id'] ?? 0);
    } elseif ($req->server['request_uri'] == '/msg') {
        $dstWorkerId = random_int(0, 4);
        if ($dstWorkerId != $http->getWorkerId()) {
            $http->sendMessage('hello ' . base64_encode(random_bytes(16)), $dstWorkerId);
            echo "[worker#" . $http->getWorkerId() . "]\tsend pipe message to " . $dstWorkerId . "\n";
        }
    }
    $resp->end('hello world');
});

$http->on('pipeMessage', function ($http, $srcWorkerId, $msg) {
    echo "[worker#" . $http->getWorkerId() . "]\treceived pipe message[$msg] from " . $srcWorkerId . "\n";
});

$http->addProcess(new \Swoole\Process(function () {
    echo "user process, id=" . \Swoole\Thread::getId() . "\n";
    sleep(2);
}));

$http->on('Task', function ($server, $taskId, $srcWorkerId, $data) {
    var_dump($taskId, $srcWorkerId, $data);
    return ['result' => uniqid()];
});

$http->on('Finish', function ($server, $taskId, $data) {
    var_dump($taskId, $data);
});

$http->on('workerStart', function ($serv, $worker_id) {
    echo "[#" . Swoole\Thread::getId() . "]\tWorker#{$worker_id} is started.\n";
});

$http->on('workerStop', function ($serv, $worker_id) {
    echo "[#" . Swoole\Thread::getId() . "]\tWorker#{$worker_id} is stopped.\n";
});

$http->on('workerExit', function (Server $serv, $worker_id) {
    echo "[#" . Swoole\Thread::getId() . "]\tWorker#{$worker_id} is exited, event_num=" . Swoole\Coroutine::stats()['event_num'] . ".\n";
});

$http->start();
