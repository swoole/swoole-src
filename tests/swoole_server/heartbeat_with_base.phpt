--TEST--
swoole_server: heart beat with SWOOLE_BASE
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_in_valgrind();
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
use Swoole\Server;
$pm = new SwooleTest\ProcessManager;
$pm->parentFunc = function ($pid) use ($pm)
{
    $client = new swoole_client(SWOOLE_SOCK_TCP, SWOOLE_SOCK_SYNC);
    if (!$client->connect('127.0.0.1', $pm->getFreePort(), 5, 0))
    {
        echo "Over flow. errno=" . $client->errCode;
        die("\n");
    }
    $s1 = time();
    Assert::same($client->recv(), '');
    $s2 = time();
    Assert::assert($s2 - $s1 > 1);
    swoole_process::kill($pid);
};

$pm->childFunc = function () use ($pm)
{
    $serv = new Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $serv->set(array(
        'heartbeat_check_interval' => 1,
        'heartbeat_idle_time' => 2,
    ));
    $serv->on("WorkerStart", function (Server $serv)  use ($pm)
    {
        $pm->wakeup();
    });
    $serv->on('receive', function (Server $serv, $fd, $rid, $data)
    {
    });
    $serv->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
