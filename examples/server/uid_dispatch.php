<?php
// Dispatch connections by uid and relay messages between bound clients.
$serv = new Swoole\Server('0.0.0.0', 9501);
$serv->fdlist = [];
$serv->set([
    'worker_num' => 4,
    'dispatch_mode' => 5,   // uid dispatch
]);
$serv->on('workerStart', function ($serv, $worker_id) {
    echo "{$worker_id} start" . PHP_EOL;
});
$serv->on('connect', function ($serv, $fd, $reactor_id) {
    echo "{$fd} connect, worker:" . $serv->worker_id . PHP_EOL;
});
$serv->on('task', function ($serv, $task_id, $reactor_id, $data) {
});
$serv->on('finish', function ($serv, $fd, $reactor_id) {
});
$serv->on('receive', function (Swoole\Server $serv, $fd, $reactor_id, $data) {
    $conn = $serv->connection_info($fd);
    print_r($conn);
    echo 'worker_id: ' . $serv->worker_id . PHP_EOL;
    if (empty($conn['uid'])) {
        $uid = $fd + 1;
        if ($serv->bind($fd, $uid)) {
            $serv->send($fd, "bind {$uid} success");
        }
    } else {
        if (empty($serv->fdlist[$fd])) {
            $serv->fdlist[$fd] = $conn['uid'];
        }
        print_r($serv->fdlist);
        foreach ($serv->fdlist as $_fd => $uid) {
            $serv->send($_fd, "{$fd} say:" . $data . PHP_EOL);
        }
    }
});
$serv->on('close', function ($serv, $fd, $reactor_id) {
    unset($serv->fdlist[$fd]);
});
$serv->start();
