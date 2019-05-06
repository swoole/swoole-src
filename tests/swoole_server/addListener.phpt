--TEST--
swoole_server: addlistener
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$simple_tcp_server = __DIR__ . "/../include/api/swoole_server/opcode_server.php";

$port1 = get_one_free_port();

$pm = new ProcessManager;
$pm->parentFunc = function ($pid)
{
    $cli = new \swoole_client(SWOOLE_SOCK_UDP, SWOOLE_SOCK_ASYNC);

    $cli->on("connect", function (\swoole_client $cli) {
        Assert::true($cli->isConnected());
        $cli->send("test");
    });

    $cli->on("receive", function(\swoole_client $cli, $data){
        $i = $cli->getpeername();
        Assert::assert($i !== false);
        $cli->send('shutdown');
        $cli->close();
    });

    $cli->on("close", function(\swoole_client $cli) {
        echo "SUCCESS\n";
    });

    $r = $cli->connect(UDP_SERVER_HOST, UDP_SERVER_PORT, 1);
    Assert::assert($r);
    Swoole\Event::wait();
};

$pm->childFunc = function () use ($pm)
{
    $serv = new \swoole_server(UDP_SERVER_HOST, UDP_SERVER_PORT, SWOOLE_BASE, SWOOLE_SOCK_UDP);
    $serv->set(["worker_num" => 1, 'log_file' => '/dev/null']);
    $serv->on("WorkerStart", function (\swoole_server $serv)  use ($pm)
    {
        $pm->wakeup();
    });
    $serv->on("Packet", function (\swoole_server $serv, $data, $clientInfo)
    {
        if (trim($data) == 'shutdown')
        {
            $serv->shutdown();
            return;
        }
        $serv->sendto($clientInfo['address'], $clientInfo['port'], $data);
    });
    $serv->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
SUCCESS