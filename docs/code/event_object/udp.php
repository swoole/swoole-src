<?php
/**
 * User: lufei
 * Date: 2020/11/29
 * Email: lufei@swoole.com
 */

use Swoole\Server\Packet;
use Swoole\Server\PipeMessage;
use Swoole\Server;

$server = new Swoole\Server('127.0.0.1', 9502, SWOOLE_PROCESS, SWOOLE_SOCK_UDP);
$server->set(
    [
        'worker_num' => 2,
        'event_object' => true,
    ]
);

//监听数据接收事件
$server->on(
    'Packet',
    function ($server, Packet $object) {
        var_dump($object);
        $server->sendMessage($object, 1 - $server->getWorkerId());
    }
);

$server->on(
    'pipeMessage',
    function (Server $serv, PipeMessage $msg) {
        var_dump($msg);
        $object = $msg->data;
        $serv->sendto($object->address, $object->port, $object->data, $object->server_socket);
    }
);

//启动服务器
$server->start();
