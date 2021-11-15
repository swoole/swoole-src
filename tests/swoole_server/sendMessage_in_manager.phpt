--TEST--
swoole_server: sendMessage in manager
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php

use Swoole\Constant;
use Swoole\Server;

require __DIR__ . '/../include/bootstrap.php';
$pm = new SwooleTest\ProcessManager;

const N = 16;

$pm->parentFunc = function ($pid) use ($pm) {
    $client = new swoole_client(SWOOLE_SOCK_TCP, SWOOLE_SOCK_SYNC);
    $client->set([
        'package_eof' => "\r\n",
        'open_eof_check' => true,
        'open_eof_split' => true,
    ]);
    if (!$client->connect('127.0.0.1', $pm->getFreePort())) {
        exit("connect failed\n");
    }
    $list = [];
    swoole_loop_n(N, function () use ($client, &$list) {
        $msg = $client->recv();
        $list[] = $msg;
        Assert::contains($msg, 'msg-');
    });
    Assert::count($list, N);
    $pm->kill();
};

$pm->childFunc = function () use ($pm) {
    $serv = new Server('127.0.0.1', $pm->getFreePort(), SWOOLE_PROCESS, SWOOLE_SOCK_TCP);
    $serv->set([
        'log_file' => '/dev/null',
        'worker_num' => 2,
        'task_worker_num' => 2,
    ]);
    $serv->on(Constant::EVENT_MANAGER_START, function (Server $serv) use ($pm) {
        $pm->wakeup();
        $pm->wait();
        usleep(10000);
        swoole_loop_n(N, function ($i) use ($serv) {
            $wid = rand(0, 3);
            $serv->sendMessage("msg-" . $i, $wid);
        });
    });
    $serv->on(Constant::EVENT_CONNECT, function ($serv, $fd, $reactor_id) use ($pm) {
        $pm->wakeup();
    });
    $serv->on(Constant::EVENT_RECEIVE, function ($serv, $fd, $reactor_id, $data) {
    });
    $serv->on(Constant::EVENT_TASK, function ($serv, $fd, $reactor_id, $data) {
    });
    $serv->on('pipeMessage', function (Server $serv, $worker_id, $data) {
        foreach ($serv->connections as $fd) {
            $serv->send($fd, $data . "\r\n");
        }
    });
    $serv->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
