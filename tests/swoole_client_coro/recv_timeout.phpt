--TEST--
swoole_client_coro: recv timeout
--SKIPIF--
<?php require  __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$pm = new ProcessManager;
$pm->parentFunc = function ($pid) use ($pm)
{
    go(function () use ($pm) {
        $cli = new Co\Client(SWOOLE_SOCK_TCP);
        $cli->connect('127.0.0.1', $pm->getFreePort(), -1);
        $data = str_repeat('A', 1025);
        $cli->send(pack('N', strlen($data)) . $data);
        $retData = @$cli->recv(0.5);
        Assert::false($retData);
        Assert::same($cli->errCode, SOCKET_ETIMEDOUT);
    });
    swoole_event_wait();
    $pm->kill();
};

$pm->childFunc = function () use ($pm) {
    $serv = new swoole_server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $serv->set([
        'worker_num' => 1,
        'log_file' => '/dev/null',
    ]);
    $serv->on("WorkerStart", function (\swoole_server $serv)  use ($pm)
    {
        $pm->wakeup();
    });
    $serv->on('receive', function (swoole_server $serv, $fd, $rid, $data)
    {
        //no response
    });
    $serv->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECTF--
