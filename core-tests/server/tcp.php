<?php
$server = new swoole_server("127.0.0.1", 9501, SWOOLE_BASE);

$server->on('receive', function ($server, $fd, $reactor_id, $data) {
    $data = trim($data);
    file_put_contents('/tmp/sw_core_tests.log', '[server/tcp]: ' . $data, FILE_APPEND);
    if ($data == 'echo') {
        $server->send($fd, "hello world\n");
    } elseif ($data == 'close') {
        $server->close($fd);
    }
});

$server->start();
