<?php
use Swoole\Process\Pool;

$pool = new Pool(1, SWOOLE_IPC_MSGQUEUE, 0x9501);
$pool->on('Message', function (Pool $pool, string $data) {
    var_dump($data);
});
$pool->start();
