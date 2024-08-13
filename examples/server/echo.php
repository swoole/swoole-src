<?php
//$serv = new Swoole\Server("0.0.0.0", 9501, SWOOLE_BASE);
// $serv = new Swoole\Server("0.0.0.0", 9501);
$serv = new Swoole\Server("0.0.0.0", 9501, SWOOLE_THREAD);

function getpid()
{
    global $serv;
    return $serv->mode === SWOOLE_THREAD ? \Swoole\Thread::getId() : posix_getpid();
}

$serv->set([
    'worker_num' => 2,
    'task_worker_num' => 3,
]);

$serv->on('workerStart', function ($serv, $worker_id) {
    echo "[#" . getpid() . "]\tWorker#{$worker_id} is started.\n";
});

$serv->on('workerStop', function ($serv, $worker_id) {
    echo "[#" . getpid() . "]\tWorker#{$worker_id} is stopped.\n";
});

$serv->on('connect', function ($serv, $fd, $reactor_id) {
    echo "[#" . getpid() . "]\tClient@[$fd:$reactor_id]: Connect.\n";
});

$serv->on('receive', function (Swoole\Server $serv, $fd, $reactor_id, $data) {
    echo "[#" . $serv->worker_id . "]\tClient[$fd] receive data: $data\n";
    if ($serv->send($fd, "hello {$data}\n") == false) {
        echo "error\n";
    }
});

$serv->on('close', function ($serv, $fd, $reactor_id) {
    echo "[#" . getpid() . "]\tClient@[$fd:$reactor_id]: Close.\n";
});

$serv->on('task', function ($serv, $src_worker_id, $task) {
    var_dump($task);
});

$serv->start();
