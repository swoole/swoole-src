<?php
$serv = new swoole_server('127.0.0.1', 9001);

for($port = 9002; $port < 9999; $port++)
{
    $serv->listen("127.0.0.1", $port, SWOOLE_SOCK_TCP);
}

$serv->on("receive", function($serv, $fd, $reactor_id, $data) {
    $info = $serv->getClientInfo($fd);
    var_dump($info);
});

$serv->start();

