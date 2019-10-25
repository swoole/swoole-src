--TEST--
swoole_client_sync: select
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Client;
use Swoole\Server;
use SwooleTest\ProcessManager;

const TIMEOUT = 0.05;

$pm = new ProcessManager;
$pm->parentFunc = function ($pid) use ($pm)
{
    $client = new Client(SWOOLE_SOCK_TCP, SWOOLE_SOCK_SYNC);
    if (!$client->connect(TCP_SERVER_HOST, $pm->getFreePort(), -1))
    {
        exit("connect failed. Error: {$client->errCode}\n");
    }
    $r = [$client];
    $w = $e = null;
    $client->send("hello world\n");
    swoole_select($r, $w, $e);
    echo $client->recv();
    $client->close();
    $pm->kill();
};

$pm->childFunc = function () use ($pm)
{
    $serv = new Server(TCP_SERVER_HOST, $pm->getFreePort(), SWOOLE_BASE, SWOOLE_SOCK_TCP);
    $serv->set([
        "worker_num" => 1,
        'log_file' => '/dev/null',
    ]);
    $serv->on("WorkerStart", function (Server $serv)  use ($pm) {
        $pm->wakeup();
    });
    $serv->on("Receive", function (Server $serv, $fd, $rid, $data) {
        $serv->send($fd, "hello world\n");
    });
    $serv->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
hello world
