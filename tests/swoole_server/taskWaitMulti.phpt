--TEST--
swoole_server: taskWaitMulti
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
$port = get_one_free_port();

$pm = new ProcessManager;
$pm->parentFunc = function ($pid) use ($port)
{
    $cli = new swoole_client(SWOOLE_SOCK_TCP, SWOOLE_SOCK_SYNC);
    $cli->connect("127.0.0.1", $port, 0.5) or die("ERROR");

    $cli->send("task-01") or die("ERROR");
    assert($cli->recv() == 'OK');
    $cli->send("task-02") or die("ERROR");
    assert($cli->recv() == 'OK');
    $cli->close();
    swoole_process::kill($pid);
};

$pm->childFunc = function () use ($pm, $port)
{
    ini_set('swoole.display_errors', 'Off');
    $serv = new swoole_server("127.0.0.1", $port);
    $serv->set(array(
        "worker_num" => 1,
        'task_worker_num' => 1,
        'log_file' => '/dev/null',
    ));
    $serv->on("WorkerStart", function (\swoole_server $serv)  use ($pm)
    {
        $pm->wakeup();
    });
    $serv->on('receive', function (swoole_server $serv, $fd, $rid, $data)
    {
        if ($data == 'task-01')
        {
            $tasks[] = mt_rand(1000, 9999);
            $tasks[] = mt_rand(1000, 9999);
            $tasks[] = mt_rand(1000, 9999);
            $tasks[] = mt_rand(1000, 9999);
            $results = $serv->taskWaitMulti($tasks, 2);
        }
        else
        {
            $tasks[] = mt_rand(1000, 9999);
            $tasks[] = mt_rand(1000, 9999);
            $tasks[] = mt_rand(1000, 9999);
            $tasks[] = mt_rand(1000, 9999);
            $tasks[] = 0;
            $results = $serv->taskWaitMulti($tasks, 0.2);
        }
        if (count($results) == 4)
        {
            $serv->send($fd, 'OK');
        }
        else
        {
            $serv->send($fd, 'ERR');
        }
    });

    $serv->on('task', function (swoole_server $serv, $task_id, $worker_id, $data)
    {
        if ($data == 0)
        {
            usleep(300000);
        }
        return $data;
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
