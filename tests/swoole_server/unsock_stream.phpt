--TEST--
swoole_server: unix socket dgram server

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

$pm->parentFunc = function ($pid)
{
    $client = new \swoole_client(SWOOLE_SOCK_UNIX_STREAM, SWOOLE_SOCK_SYNC);
    $r = $client->connect(UNIXSOCK_SERVER_PATH, 0, -1);
    if ($r === false)
    {
        echo "ERROR";
        exit;
    }
    $client->send("SUCCESS");
    echo $client->recv();
    $client->close();
};

$pm->childFunc = function () use ($pm)
{
    $serv = new \swoole_server(UNIXSOCK_SERVER_PATH, 0, SWOOLE_BASE, SWOOLE_SOCK_UNIX_STREAM);
    $serv->set(["worker_num" => 1, ]);
    $serv->on("WorkerStart", function (\swoole_server $serv)  use ($pm)
    {
        $pm->wakeup();
        swoole_timer_after(1000, function () use ($serv)
        {
            @unlink(UNIXSOCK_SERVER_PATH);
            $serv->shutdown();
        });
    });
    $serv->on("Receive", function (\swoole_server $serv, $fd, $reactorId, $data)
    {
        $serv->send($fd, 'SUCCESS');
    });
    $serv->start();
};

$pm->childFirst();
$pm->run();

?>

--EXPECT--
SUCCESS
