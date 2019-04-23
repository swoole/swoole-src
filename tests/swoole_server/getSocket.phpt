--TEST--
swoole_server: getSocket
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$port = get_one_free_port();

$pm = new ProcessManager;
$pm->parentFunc = function ($pid) use ($port)
{
    $cli = new \swoole_client(SWOOLE_SOCK_TCP, SWOOLE_SOCK_ASYNC);

    $cli->on("connect", function (\swoole_client $cli) {
        Assert::true($cli->isConnected());
        $cli->send("test");
    });

    $cli->on("receive", function(\swoole_client $cli, $data){
        Assert::eq($data, 'Socket');
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
    Assert::assert($r);
    Swoole\Event::wait();
};

$pm->childFunc = function () use ($pm, $port)
{
    $serv = new \swoole_server(TCP_SERVER_HOST, $port);
    $socket = $serv->getSocket();
    $serv->set([
        "worker_num" => 1,
        'log_file' => '/dev/null',
    ]);
    $serv->on("WorkerStart", function (\swoole_server $serv)  use ($pm)
    {
        $pm->wakeup();
    });
    $serv->on("Receive", function (\swoole_server $serv, $fd, $rid, $data) use ($socket)
    {
        if (trim($data) == 'shutdown')
        {
            $serv->shutdown();
            return;
        }
        else {
            $serv->send($fd, get_resource_type($socket));
        }
    });
    $serv->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
SUCCESS