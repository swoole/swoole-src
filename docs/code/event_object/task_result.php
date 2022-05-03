<?php
/**
 * User: lufei
 * Date: 2020/11/29
 * Email: lufei@swoole.com
 */

use Swoole\Server;
use Swoole\Server\TaskResult;

$server = new Server('127.0.0.1', 9501, SWOOLE_PROCESS);
$server->set(
    [
        'task_worker_num' => 4,
        'worker_num' => 1,
        'event_object' => true,
    ]
);


$server->on(
    'receive',
    function (Server $server, $object) {
        $n = 3;
        while ($n--) {
            $server->task($object);
        }
    }
);

$server->on(
    'task',
    function ($server, $task) {
        var_dump($task);
        $server->finish(['data' => str_repeat('A', 2), 'task' => $task->data]);
    }
);

$server->on(
    'finish',
    function ($server, $result) {
        var_dump($result);
        static $count = 0;
        $count++;
        if ($count == 3) {
            $server->send($result->data['task']->fd, 'hello world');
        }
    }
);

$server->start();