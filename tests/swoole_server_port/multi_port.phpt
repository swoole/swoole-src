--TEST--
swoole_server_port: swoole server port
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$port1 = get_one_free_port();
$port2 = get_one_free_port();
$port3 = get_one_free_port();

$pm = new ProcessManager;

$pm->parentFunc = function ($pid) use ($pm, $port1, $port2, $port3)
{
    makeTcpClient_without_protocol(TCP_SERVER_HOST, $port1, function(\swoole_client $cli) use($port1) {
        $r = $cli->send("$port1\r\n");
        assert($r !== false);
    }, function(\swoole_client $cli, $data) use($port1) {
        Assert::eq($data, $port1);
        $cli->close();
    });

    makeTcpClient_without_protocol(TCP_SERVER_HOST, $port2, function(\swoole_client $cli) use($port2) {
        $r = $cli->send("$port2\n");
        assert($r !== false);
    }, function(\swoole_client $cli, $data) use($port2) {
        Assert::eq($data, $port2);
        $cli->close();
    });

    makeTcpClient_without_protocol(TCP_SERVER_HOST, $port3, function(\swoole_client $cli) use($port1, $port3) {
        $r = $cli->send("$port3\r");
        assert($r !== false);
    }, function(\swoole_client $cli, $data) use($port1, $port3) {
        Assert::eq($data, $port1);
        $cli->close();
    });
    swoole_event_wait();
    $pm->kill();
};

$pm->childFunc = function () use ($pm,  $port1, $port2, $port3)
{
    $server = new swoole_server('127.0.0.1', $port1);
    $server->set(array(
        'log_file' => '/dev/null',
        'worker_num' => 1,
    ));

    $p2 = $server->listen('127.0.0.1', $port2, SWOOLE_SOCK_TCP);
    $p2->on('receive', function ($serv, $fd, $tid, $data) use ($port2)
    {
        $serv->send($fd, $port2);
    });

    $server->listen('127.0.0.1', $port3, SWOOLE_SOCK_TCP);

    $server->on('Receive', function ($serv, $fd, $rid, $data)  use ($port1)
    {
        $serv->send($fd, "$port1");
    });

    $server->on("WorkerStart", function (\swoole_server $serv)
    {
        /**
         * @var $pm ProcessManager
         */
        global $pm;
        $pm->wakeup();
    });
    $server->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
close
close
close
