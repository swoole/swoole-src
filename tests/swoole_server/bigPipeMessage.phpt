--TEST--
swoole_server: send big pipe message
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Server;
$port = get_one_free_port();
const N = 800000;

$pm = new SwooleTest\ProcessManager;

$pm->parentFunc = function ($pid) use ($port, $pm)
{
    Co\Run(function () use ($port) {
        $cli = new Swoole\Coroutine\Client(SWOOLE_SOCK_TCP);
        $r = $cli->connect(TCP_SERVER_HOST, $port, 1);
        Assert::assert($r);
        $cli->send("test");
        $data = $cli->recv();
        echo $data;
        $cli->close();
    });
    $pm->kill();
};

$pm->childFunc = function () use ($pm, $port)
{
    $serv = new Server(TCP_SERVER_HOST, $port);
    $serv->set([
        "worker_num" => 2,
        'log_file' => '/dev/null',
    ]);
    $serv->on("WorkerStart", function (Server $serv) use ($pm)
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
