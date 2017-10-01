--TEST--
swoole_server: connection iterator
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
const N = 10;

global $count;
$count = 0;
$port = get_one_free_port();

$pm = new ProcessManager;
$pm->parentFunc = function ($pid) use ($port)
{
    global $count;
    for ($i = 0; $i < N; $i++)
    {
        $cli = new swoole_client(SWOOLE_SOCK_TCP, SWOOLE_SOCK_ASYNC);
        $cli->on("connect", function (swoole_client $cli)
        {

        });
        $cli->on("receive", function (swoole_client $cli, $data)
        {
            assert($data == "OK");
            global $count;
            $count ++;
            $cli->close();
        });
        $cli->on("error", function (swoole_client $cli)
        {
            echo "error\n";
        });
        $cli->on("close", function (swoole_client $cli)
        {

        });
        $cli->connect("127.0.0.1", $port, 0.1);
    }
    swoole_event::wait();
    assert($count == N);
    swoole_process::kill($pid);
};

$pm->childFunc = function () use ($pm, $port)
{
    $serv = new swoole_server("127.0.0.1", $port, SWOOLE_BASE);
    $serv->set(array(
        "worker_num" => 1,
        'log_file' => '/dev/null',
    ));
    $serv->on("WorkerStart", function (\swoole_server $serv)  use ($pm)
    {
        $pm->wakeup();
    });
    $serv->on('connect', function (swoole_server $serv, $fd, $rid)
    {
        global $count;
        $count++;
        if ($count == N)
        {
            $serv->defer(function () use ($serv)
            {
                foreach ($serv->connections as $fd)
                {
                    $serv->send($fd, "OK");
                }
            });
        }
    });
    $serv->on('receive', function (swoole_server $serv, $fd, $rid, $data)
    {

    });
    $serv->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
