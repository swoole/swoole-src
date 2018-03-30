<?php
$pool = new Swoole\Process\Pool(2, SWOOLE_IPC_MSGQUEUE, 0x7000001);

$pool->on("Message", function ($pool, $message) {
    echo "Message: {$message}\n";
});

$pool->on("WorkerStart", function ($pool, $workerId) {
    echo "Worker#{$workerId} is started\n";
});

$pool->on("WorkerStop", function ($pool, $workerId) {
    echo "Worker#{$workerId} is stopped\n";
});

$pool->listen('127.0.0.1', 8089);

$pool->start();
