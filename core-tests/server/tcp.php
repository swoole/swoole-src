<?php
$server = new swoole_server("127.0.0.1", 9501, SWOOLE_BASE);

const LOG_FILE = __DIR__.'/core_tests.log';

$server->on('receive', function ($server, $fd, $reactor_id, $data) {
    $data = trim($data);
    file_put_contents(LOG_FILE, '[server/tcp]: ' . $data . "\n", FILE_APPEND);
    if ($data == 'echo') {
        $server->send($fd, "hello world\n");
    } elseif ($data == 'close') {
        $server->close($fd);
    }
});

$server->on('shutdown', function () {
    unlink(LOG_FILE);
});

$server->start();
