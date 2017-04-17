<?php
$server = new Swoole\WebSocket\Server('127.0.0.1', 9501, SWOOLE_BASE);

$server->on('Message', function($serv, $message) {

    $mysql = new Swoole\Coroutine\MySQL();
    $res = $mysql->connect(['host' => '127.0.0.1', 'user' => 'root', 'password' => 'root', 'database' => 'test']);
    if ($res == false) {
        $serv->push($message->fd, "MySQL connect fail!");
        return;
    }
    $ret = $mysql->query('show tables', 2);
    $serv->push($message->fd, "swoole response is ok, result=".var_export($ret, true));
});

$server->start();
