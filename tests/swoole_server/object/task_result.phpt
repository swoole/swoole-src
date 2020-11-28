--TEST--
swoole_server/object: task result
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

use Swoole\Server;
use Swoole\Client;
use Swoole\Server\TaskResult;

$pm = new SwooleTest\ProcessManager;

const N = 12;

$pm->parentFunc = function ($pid) use ($pm) {
    $cli = new Client(SWOOLE_SOCK_TCP, SWOOLE_SOCK_SYNC);
    $cli->connect('127.0.0.1', $pm->getFreePort(), 10) or die("ERROR");
    $cli->send("task-01") or die("ERROR");
    Assert::same($cli->recv(), "hello world");
    $cli->close();
    $pm->kill();
};

$pm->childFunc = function () use ($pm) {
    $server = new Server('127.0.0.1', $pm->getFreePort(), SWOOLE_PROCESS);
    $server->set([
        'log_level' => SWOOLE_LOG_NOTICE,
        'task_worker_num' => 4,
        'worker_num' => 1,
        'event_object' => true,
        'enable_coroutine' => false,
    ]);

    $server->on('workerStart', function () use ($pm) {
        $pm->wakeup();
    });

    $server->on('receive', function (Server $server, $object) {
        $n = N;
        while ($n--) {
            $server->task($object);
        }
    });

    $server->on('task', function ($server, $task) {
        $server->finish(['data' => str_repeat('A', 8000), 'task' => $task->data]);
    });

    $server->on('finish', function ($server, $result) {
        static $count = 0;
        $count++;
        if ($count == N) {
            $server->send($result->data['task']->fd, 'hello world');
        }
    });

    $server->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECTF--
