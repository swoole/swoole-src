--TEST--
swoole_server: send message [02]
--SKIPIF--
<?php require __DIR__ . "/../include/skipif.inc"; ?>
--INI--
assert.active=1
assert.warning=1
assert.bail=0
assert.quiet_eval=0

--FILE--
<?php
require_once __DIR__ . "/../include/swoole.inc";
$pm = new ProcessManager;

$pm->parentFunc = function ($pid) use ($pm)
{
    $client = new swoole_client(SWOOLE_SOCK_TCP, SWOOLE_SOCK_SYNC);
    $client->set([
        'package_eof' => "\r\n",
        'open_eof_check' => true,
        'open_eof_split' => true,
    ]);
    if (!$client->connect('127.0.0.1', 9501))
    {
        exit("connect failed\n");
    }
    $list = [];
    for ($i = 0; $i < 7; $i++)
    {
        $data = $client->recv();
        if ($data === false or $data === '')
        {
            echo "ERROR\n";
            break;
        }
        $list[] = intval($data);
    }
    sort($list);
    assert($list == range(0, 6));
    $pm->kill();
};

$pm->childFunc = function () use ($pm)
{
    $serv = new swoole_server("127.0.0.1", 9501, SWOOLE_PROCESS, SWOOLE_SOCK_TCP );
    $serv->set([
        'log_file' => '/dev/null',
        'worker_num' => 4,
        'task_worker_num' => 3,
    ]);

    $lock = new swoole\lock();

    $process = new \Swoole\Process(function ($process) use ($serv) {
        while (true)
        {
            $r = $process->read();
            if (!$r)
            {
                continue;
            }
            $cmd = json_decode($r, true);
            for ($i = 0; $i < ($serv->setting['worker_num'] + $serv->setting['task_worker_num']); $i++)
            {
                $serv->sendMessage(['worker_id' => $i, 'fd' => $cmd['fd']], $i);
            }
        }
    });

    $serv->addProcess($process);
    $serv->on("workerStart", function ($serv) use ($pm)
    {
        $pm->wakeup();
    });
    $serv->on('connect', function (swoole_server $serv, $fd) use ($process) {
        $process->write(json_encode(["fd" => $fd]));
    });
    $serv->on('receive', function ($serv, $fd, $from_id, $data) {

    });

    $serv->on('pipeMessage', function (swoole_server $serv, $worker_id, $data) use ($lock) {
        //$lock->lock();
        $serv->send($data['fd'], $data['worker_id']."\r\n");
        //$lock->unlock();
    });

    $serv->on('task', function (swoole_server $serv, $task_id, $worker_id, $data)
    {

    });

    $serv->on('finish', function (swoole_server $serv, $fd, $rid, $data)
    {

    });

    $serv->start();
};


$pm->childFirst();
$pm->run();
?>
--EXPECT--
