--TEST--
swoole_server/task: idle_worker_num
--SKIPIF--
<?php
require __DIR__ . '/../../include/skipif.inc';
?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';
$pm = new SwooleTest\ProcessManager;

use Swoole\Server;
use Swoole\Client;
use Swoole\Atomic;
use Swoole\Timer;

$atomic = new Atomic();

$pm->parentFunc = function ($pid) use ($pm) {
    $client = new Client(SWOOLE_SOCK_TCP, SWOOLE_SOCK_SYNC);
    if (!$client->connect('127.0.0.1', $pm->getFreePort())) {
        exit("connect failed\n");
    }
    $client->send("hello world");
    $data = $client->recv();
    Assert::assert($data);
    $json = json_decode($data);
    Assert::eq($json->task_idle_worker_num, 1);
    $pm->kill();
};

$pm->childFunc = function () use ($pm, $atomic) {
    $serv = new Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE, SWOOLE_SOCK_TCP);
    $serv->set([
        'worker_num' => 1,
        'task_worker_num' => 3,
        'log_level' => SWOOLE_LOG_ERROR,
        'task_use_object' => true,
    ]);
    $serv->on("workerStart", function (Server $serv, $wid) use ($pm, $atomic) {
        if ($atomic->add() == $serv->setting['worker_num'] + $serv->setting['task_worker_num']) {
            Timer::after(1, function () use ($pm) {
                $pm->wakeup();
            });
        }
    });
    $serv->on('receive', function (Server $serv, $fd, $tid, $data) {
        $serv->task(['sleep' => 1,]);
        $serv->task(['fd' => $fd,]);
    });
    $serv->on('Task', function (Server $server, Server\Task $task) {
        if (isset($task->data['sleep'])) {
            sleep($task->data['sleep']);
        } else {
            $server->send($task->data['fd'], json_encode($server->stats()));
        }
    });
    $serv->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
