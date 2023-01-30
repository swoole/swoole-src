--TEST--
swoole_server: send message [3]
--SKIPIF--
<?php use Swoole\Process;

require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
$pm = new SwooleTest\ProcessManager;

$pm->parentFunc = function ($pid) use ($pm) {
    $client = new Swoole\Client(SWOOLE_SOCK_TCP, SWOOLE_SOCK_SYNC);
    $client->set([
        'package_eof' => "\r\n",
        'open_eof_check' => true,
        'open_eof_split' => true,
    ]);
    if (!$client->connect('127.0.0.1', $pm->getFreePort())) {
        exit("connect failed\n");
    }
    echo $client->recv();
    $pm->kill();
};

$pm->childFunc = function () use ($pm) {
    $serv = new Swoole\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_PROCESS, SWOOLE_SOCK_TCP);
    $serv->set([
        'log_file' => '/dev/null',
        'worker_num' => 2,
    ]);
    $serv->on("workerStart", function ($serv, $wid) use ($pm) {
        if ($wid == 0) {
            $pm->wakeup();
        }
    });
    $serv->on('connect', function (Swoole\Server $serv, $fd) {
        $wid = $serv->getWorkerId();
        $serv->sendMessage([
            'fd' => $fd,
            'worker_id' => $wid,
            'data' => random_bytes(random_int(1024 * 1024, 2 * 1024 * 1024)),
        ], 1 - $wid);
    });
    $serv->on('receive', function ($serv, $fd, $reactor_id, $data) {

    });

    $serv->on('pipeMessage', function (Swoole\Server $serv, $worker_id, $data) {
        $serv->send($data['fd'], "OK\r\n");
    });

    $serv->on('task', function (Swoole\Server $serv, $task_id, $worker_id, $data) {

    });

    $serv->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
OK
