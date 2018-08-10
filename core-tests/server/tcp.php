<?php
$server = new swoole_server("127.0.0.1", 9501, SWOOLE_BASE);

$server->on('receive', function ($server, $fd, $reactor_id, $data) {
    $data = trim($data);
    if ($data == 'echo') {
        $server->send($fd, "hello world\n");
    } elseif ($data == 'close') {
        $server->close($fd);
    }
});

$server->start();
