--TEST--
swoole_server: task callback
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
$port = 9508;
const N = 2048;

$pm = new ProcessManager;
$pm->parentFunc = function ($pid) use ($port, $pm)
{
    $cli = new swoole_client(SWOOLE_SOCK_TCP, SWOOLE_SOCK_SYNC);
    $cli->connect("127.0.0.1", $port, 10) or die("ERROR");
    $cli->send("task-01") or die("ERROR");
    echo $cli->recv();
    $cli->close();
    $pm->kill();
};

$pm->childFunc = function () use ($pm, $port)
{
    ini_set('swoole.display_errors', 'Off');
    $serv = new swoole_server("127.0.0.1", $port, SWOOLE_BASE);
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
        for ($i = 0; $i < 2048; $i++)
        {
            $data = array('id' => $i, 'fd' => $fd, 'data' => openssl_random_pseudo_bytes(rand(2048, 4096)));
            if ($serv->task($data) === false)
            {
                $serv->send($fd, "ERROR\n");
                return;
            }
        }
    });

    $serv->on('task', function (swoole_server $serv, $task_id, $worker_id, $data)
    {
        if ($task_id == 0)
        {
            sleep(1);
        }
        if ($task_id != $data['id'])
        {
            echo "ERROR, $task_id, {$data['id']}\n";
        }
        if ($data['id'] == N - 1)
        {
            $serv->send($data['fd'], "OK");
        }
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
OK