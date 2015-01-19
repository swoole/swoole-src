<?php
$frame_server = new swoole_server("127.0.0.1", 9501, SWOOLE_FRAME | SWOOLE_PROCESS);

$frame_server->on('receive', function (swoole_server $serv, $fd, $from_id, $data) {
    echo "recv ".strlen($data)." bytes\n";
    $serv->send($fd, "hello world\n");
});


$frame_server->start();