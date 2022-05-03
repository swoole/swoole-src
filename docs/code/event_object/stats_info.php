<?php
/**
 * User: lufei
 * Date: 2020/11/29
 * Email: lufei@swoole.com
 */

use Swoole\Server;
use Swoole\Server\Event;
use Swoole\Server\StatusInfo;

$serv = new Server('127.0.0.1', 9501);
$serv->set(
    array(
        'worker_num' => 1,
        'event_object' => true,
    )
);
$serv->on(
    'Connect',
    function (Server $serv, Event $object) {
        var_dump($object);
    }
);
$serv->on(
    'Close',
    function (Server $serv, Event $object) {
        var_dump($object);
    }
);
$serv->on(
    'receive',
    function (Server $serv, Event $object) {
        var_dump($object);
        $serv->send($object->fd, json_encode(['worker' => $serv->getWorkerId(), 'data' => $object->data]));
    }
);
$serv->on(
    'WorkerError',
    function (Server $serv, StatusInfo $info) {
        var_dump($info);
    }
);
$serv->start();
