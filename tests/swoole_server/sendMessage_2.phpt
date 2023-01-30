--TEST--
swoole_server: send message [02]
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
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
    $list = [];
    for ($i = 0; $i < 7; $i++) {
        $data = $client->recv();
        if ($data === false or $data === '') {
            echo "ERROR\n";
            break;
        }
        $list[] = intval($data);
    }
    sort($list);
    Assert::same($list, range(0, 6));
    $pm->kill();
};

$pm->childFunc = function () use ($pm) {
    $serv = new Swoole\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_PROCESS, SWOOLE_SOCK_TCP);
    $serv->set([
        'log_file' => '/dev/null',
        'worker_num' => 4,
        'task_worker_num' => 3,
    ]);

    $process = new \Swoole\Process(function ($process) use ($serv) {
        while (true) {
            $r = $process->read();
            if (!$r) {
                continue;
            }
            $cmd = json_decode($r, true);
            for ($i = 0; $i < ($serv->setting['worker_num'] + $serv->setting['task_worker_num']); $i++) {
                $serv->sendMessage(['worker_id' => $i, 'fd' => $cmd['fd']], $i);
            }
        }
    });

    $serv->addProcess($process);
    $serv->on("workerStart", function ($serv, $wid) use ($pm) {
        if ($wid == 0) {
            $pm->wakeup();
        }
    });
    $serv->on('connect', function (Swoole\Server $serv, $fd) use ($process) {
        $process->write(json_encode(["fd" => $fd]));
    });
    $serv->on('receive', function ($serv, $fd, $reactor_id, $data) {

    });

    $serv->on('pipeMessage', function (Swoole\Server $serv, $worker_id, $data) {
        $serv->send($data['fd'], $data['worker_id'] . "\r\n");
    });

    $serv->on('task', function (Swoole\Server $serv, $task_id, $worker_id, $data) {

    });

    $serv->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
