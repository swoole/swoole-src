<?php
// A tiny Redis-compatible server that answers PING and GET.
// Run: php examples/server/redis_server.php, then `redis-cli -p 9508 ping`
use Swoole\Redis\Server;

$server = new Server('127.0.0.1', 9508);
$server->setHandler('PING', function ($fd, $data) {
    return Server::format(Server::STATUS, 'PONG');
});
$server->setHandler('GET', function ($fd, $data) {
    return Server::format(Server::STRING, 'hello from swoole');
});
$server->start();
