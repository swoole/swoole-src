--TEST--
swoole_server: addProcess
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
    $cli = new \swoole_client(SWOOLE_SOCK_TCP, SWOOLE_SOCK_ASYNC);

    $cli->on("connect", function (\swoole_client $cli) {
        assert($cli->isConnected() === true);
        $cli->send("test");
    });

    $cli->on("receive", function(\swoole_client $cli, $data){
        assert($data == 'test');
        $cli->send('shutdown');
        $cli->close();
    });

    $cli->on("close", function(\swoole_client $cli) {
        echo "SUCCESS\n";
    });

    $cli->on("error", function(\swoole_client $cli) {
        echo "error\n";
    });

    $r = $cli->connect(TCP_SERVER_HOST, $port, 1);
    assert($r);
    Swoole\Event::wait();
};

$pm->childFunc = function () use ($pm, $port)
{
    $serv = new \swoole_server(TCP_SERVER_HOST, $port);
    $process = new \Swoole\Process(function ($process) use ($serv)
    {
        while (1)
        {
            $msg = json_decode($process->read(), true);
            $serv->send($msg['fd'], $msg['data']);
        }
    });
    $serv->set([
        "worker_num" => 1,
        'log_file' => '/dev/null',
    ]);
    $serv->on("WorkerStart", function (\swoole_server $serv)  use ($pm)
    {
        $pm->wakeup();
    });
    $serv->on("Receive", function (\swoole_server $serv, $fd, $rid, $data) use ($process)
    {
        if (trim($data) == 'shutdown')
        {
            $serv->shutdown();
            return;
        }
        else {
            $process->write(json_encode(['fd' => $fd, 'data' => $data]));
        }
    });
    $serv->addProcess($process);
    $serv->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
SUCCESS