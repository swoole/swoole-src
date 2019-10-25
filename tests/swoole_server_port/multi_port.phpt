--TEST--
swoole_server_port: swoole server port
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine\Client;
use Swoole\Timer;
use Swoole\Event;
use Swoole\Server;

$port1 = get_one_free_port();
$port2 = get_one_free_port();
$port3 = get_one_free_port();

function makeTcpClient_without_protocol($host, $port, callable $onConnect = null, callable $onReceive = null)
{
    go(function () use ($host, $port, $onConnect, $onReceive) {
        $cli = new Client(SWOOLE_SOCK_TCP);
        $r = $cli->connect($host, $port, 1);
        Assert::assert($r);
        if ($onConnect) {
            $onConnect($cli);
        }
        $recv = $cli->recv();
        if ($onReceive) {
            $onReceive($cli, $recv);
        }
    });
}

$pm = new SwooleTest\ProcessManager;

$pm->parentFunc = function ($pid) use ($pm, $port1, $port2, $port3)
{
    makeTcpClient_without_protocol(TCP_SERVER_HOST, $port1, function(Client $cli) use($port1) {
        $r = $cli->send("$port1\r\n");
        Assert::assert($r !== false);
    }, function(Client $cli, $data) use($port1) {
        Assert::same((int)$data, $port1);
        $cli->close();
    });

    makeTcpClient_without_protocol(TCP_SERVER_HOST, $port2, function(Client $cli) use($port2) {
        $r = $cli->send("$port2\n");
        Assert::assert($r !== false);
    }, function(Client $cli, $data) use($port2) {
        Assert::same((int)$data, $port2);
        $cli->close();
    });

    makeTcpClient_without_protocol(TCP_SERVER_HOST, $port3, function(Client $cli) use($port1, $port3) {
        $r = $cli->send("$port3\r");
        Assert::assert($r !== false);
    }, function(Client $cli, $data) use($port1, $port3) {
        Assert::same((int)$data, $port1);
        $cli->close();
    });
    swoole_event_wait();
    $pm->kill();
};

$pm->childFunc = function () use ($pm,  $port1, $port2, $port3)
{
    $server = new Server('127.0.0.1', $port1);
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

    $server->on('Receive', function (Server $serv, $fd, $rid, $data)  use ($port1)
    {
        $serv->send($fd, "$port1");
    });

    $server->on("WorkerStart", function (Server $serv)
    {
        /**
         * @var $pm SwooleTest\ProcessManager
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
