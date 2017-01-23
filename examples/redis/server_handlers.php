<?php
use Swoole\Redis\Server;

$server = new Server("127.0.0.1", 6379, SWOOLE_BASE);

$server->setHandlers(function ($server, $fd, $command, $data) {
    var_dump($command);
    print_r($data);
    return Server::format(Server::STATUS, 'OK');
});

$server->start();

