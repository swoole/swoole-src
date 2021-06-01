<?php
use Swoole\Process;
use Swoole\Atomic;

$pool = new Process\Pool(2, SWOOLE_IPC_SOCKET);

$pool->on('WorkerStart', function (Process\Pool $pool, $workerId) {
    echo("[Worker #{$workerId}] WorkerStart\n");
    if ($workerId == 1) {

    }
});

$pool->on('WorkerStop', function (\Swoole\Process\Pool $pool, $workerId) {
    echo("[Worker #{$workerId}] WorkerStop\n");
});

$pool->on('Message', function ($pool, $msg) {
    var_dump($msg);
    $pool->detach();

    while(1) {
        sleep(1);
        echo "pid=".posix_getpid()."\n";
    };
});

$pool->listen('127.0.0.1', 8089);

$pool->start();
