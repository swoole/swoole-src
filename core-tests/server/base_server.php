<?php
$server = new Swoole\Server('0.0.0.0', 9501, SWOOLE_BASE);

$server->on('Receive', function ($s, $fd, $tid, $data) {
    file_put_contents(__DIR__.'/log', $data);
    var_dump($data);
    $s->send($fd, $data);
});

$server->start();