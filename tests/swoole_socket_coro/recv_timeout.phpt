--TEST--
swoole_socket_coro: recv timeout
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require_once __DIR__ . '/../include/bootstrap.php';
require_once __DIR__ . '/../include/swoole.inc';

$pm = new ProcessManager;

$pm->parentFunc = function ($pid) use ($pm)
{
    go(function () use ($pm) {
        $conn = new Swoole\Coroutine\Socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
        assert($conn->connect('127.0.0.1', 9501));
        $conn->send(json_encode(['data' => 'hello']));
        $ret = $conn->recv(0.2);
        assert($ret === false);
        assert($conn->errCode == SOCKET_EAGAIN);
    });
    swoole_event_wait();
    $pm->kill();
};

$pm->childFunc = function () use ($pm)
{
    $serv = new \swoole_server('127.0.0.1', 9501, SWOOLE_BASE);
    $serv->set(["worker_num" => 1, ]);
    $serv->on("WorkerStart", function (\swoole_server $serv)  use ($pm)
    {
        $pm->wakeup();
    });
    $serv->on("Receive", function (\swoole_server $serv, $fd, $reactorId, $data)
    {

    });
    $serv->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
