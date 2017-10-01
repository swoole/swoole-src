--TEST--
swoole_server: taskwait
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

    $cli->send("array-01") or die("ERROR");
    assert($cli->recv() == 'OK');
    $cli->send("array-02") or die("ERROR");
    assert($cli->recv() == 'OK');
    $cli->send("string-01") or die("ERROR");
    assert($cli->recv() == 'OK');
    $cli->send("string-02") or die("ERROR");
    assert($cli->recv() == 'OK');
    $cli->send("timeout") or die("ERROR");
    assert($cli->recv() == 'OK');

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
        if ($data == 'array-01')
        {
            $res = $serv->taskwait(['type' => 'array', 'value' => $data]);
            if (!empty($res['name']))
            {
                $serv->send($fd, 'OK');
            }
            else
            {
                $serv->send($fd, 'ERR');
            }
        }
        elseif ($data == 'array-02')
        {
            $res = $serv->taskwait(['type' => 'string', 'value' => $data]);
            if ($res == "hello world\n")
            {
                $serv->send($fd, 'OK');
            }
            else
            {
                $serv->send($fd, 'ERR');
            }
        }
        elseif ($data == 'string-01')
        {
            $res = $serv->taskwait('array');
            if (!empty($res['name']))
            {
                $serv->send($fd, 'OK');
            }
            else
            {
                $serv->send($fd, 'ERR');
            }
        }
        elseif ($data == 'string-02')
        {
            $res = $serv->taskwait('string');
            if ($res == "hello world\n")
            {
                $serv->send($fd, 'OK');
            }
            else
            {
                $serv->send($fd, 'ERR');
            }
        }
        elseif ($data == 'timeout')
        {
            $res = $serv->taskwait('timeout', 0.2);
            if ($res === false)
            {
                $res = $serv->taskwait('string', 0.2);
                if ($res === "hello world\n")
                {
                    $serv->send($fd, 'OK');
                    return;
                }
            }
            $serv->send($fd, 'ERR');
        }
    });

    $serv->on('task', function (swoole_server $serv, $task_id, $worker_id, $data)
    {
        if (is_array($data))
        {
            if ($data['type'] == 'array')
            {
                return array('name' => 'rango', 'year' => 1987);
            }
            else
            {
                return "hello world\n";
            }
        }
        else
        {
            if ($data == 'array')
            {
                return array('name' => 'rango', 'year' => 1987);
            }
            elseif ($data == 'string')
            {
                return "hello world\n";
            }
            elseif ($data == 'timeout')
            {
                usleep(300000);
                return "task timeout\n";
            }
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
