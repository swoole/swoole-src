<?php

use Swoole\Server;

$serv = new Server('127.0.0.1', 9501);

$serv->on('receive', function (Server $serv, $fd, $from_id, $data) {
    echo '[#'.$serv->worker_id."]\tClient[$fd]: $data\n";
    if (false == $serv->send($fd, "hello\n")) {
        echo "error\n";
    }
});

$serv->start();
