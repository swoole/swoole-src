<?php

use Swoole\Coroutine\Server;
use Swoole\Coroutine\Server\Connection;

go(function () {
    $server = new Server('0.0.0.0', 9501, false);

    $server->handle(function (Connection $conn) {
        while (true) {

            $data = $conn->recv();
            if (!$data) {
                break;
            }
            $conn->send("hello $data");
        }
        $conn->close();
    });

    $server->start();
});

swoole_event::wait();