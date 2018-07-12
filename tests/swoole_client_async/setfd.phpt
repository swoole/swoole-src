--TEST--
swoole_client: async setfd

--SKIPIF--
<?php require  __DIR__ . '/../include/skipif.inc'; ?>
--INI--
assert.active=1
assert.warning=1
assert.bail=0
assert.quiet_eval=0


--FILE--
<?php
require_once __DIR__ . '/../include/bootstrap.php';
require_once __DIR__ . '/../include/swoole.inc';

$port = get_one_free_port();
$pm = new ProcessManager;
$pm->parentFunc = function ($pid) use ($pm, $port)
{
    $cli = new swoole_client(SWOOLE_SOCK_TCP);
    $cli->connect(TCP_SERVER_HOST, $port);
    echo 'connected';
    $c = new swoole_client(SWOOLE_SOCK_TCP | SWOOLE_ASYNC);
    $c->on('connect', function($c){echo 'connected';$c->send('test');});
    $c->on('error', function(){});
    $c->on('receive', function($c, $data){echo $data;exit;});
    $c->on('close', function(){});
    $c->setfd($cli->sock);
    while (true) {
        swoole_event_dispatch();
    }
};

$pm->childFunc = function () use ($pm, $port)
{
    $serv = new \swoole_server(TCP_SERVER_HOST, $port, SWOOLE_BASE, SWOOLE_SOCK_TCP);
    $serv->set([
        "worker_num" => 1,
        'log_file' => '/dev/null'
    ]);
    $serv->on("WorkerStart", function (\swoole_server $serv)  use ($pm)
    {
        $pm->wakeup();
    });
    $serv->on("Receive", function (\swoole_server $serv, $fd, $rid, $data)
    {
        echo $data;
        $serv->send($fd, $data);
        $serv->shutdown();
    });
    $serv->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
connectedconnectedtesttest