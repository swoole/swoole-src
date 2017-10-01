--TEST--
swoole_server: send big pipe message
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

const N = 800000;

$pm = new ProcessManager;
$pm->parentFunc = function ($pid) use ($port)
{
    $cli = new \swoole_client(SWOOLE_SOCK_TCP, SWOOLE_SOCK_ASYNC);

    $cli->on("connect", function (\swoole_client $cli) {
        $cli->send("test");
    });

    $cli->on("receive", function(\swoole_client $cli, $data){
        echo $data;
        $cli->close();
    });

    $cli->on("close", function(\swoole_client $cli) {

    });

    $cli->on("error", function(\swoole_client $cli) {

    });

    $cli->connect(TCP_SERVER_HOST, $port, 1);
    Swoole\Event::wait();
    Swoole\Process::kill($pid);
};

$pm->childFunc = function () use ($pm, $port)
{
    $serv = new \swoole_server(TCP_SERVER_HOST, $port);
    $serv->set([
        "worker_num" => 2,
        'log_file' => '/dev/null',
    ]);
    $serv->on("WorkerStart", function (\swoole_server $serv) use ($pm)
    {
        $pm->wakeup();
    });
    $serv->on("pipeMessage", function ($serv, $worker_id, $data)
    {
        if (is_array($data) and strlen($data['data']) == N)
        {
            $serv->send($data['fd'], "OK\n");
        }
    });
    $serv->on("receive", function ($serv, $fd, $rid, $data)
    {
        $data = str_repeat("A", N);
        $serv->sendMessage(array('data' => $data, 'fd' => $fd), 1 - $serv->worker_id);
    });
    $serv->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
OK
