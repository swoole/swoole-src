--TEST--
swoole_socket_coro: recv timeout
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require_once __DIR__ . '/../include/bootstrap.php';

$pm = new ProcessManager;
$port = get_one_free_port();
$pm->parentFunc = function ($pid) use ($pm, $port)
{
    go(function () use ($pm, $port) {
        $conn = new Swoole\Coroutine\Socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
        assert($conn->connect('127.0.0.1', $port));
        $conn->send(json_encode(['data' => 'hello']));
        $ret = $conn->recv(1024, 0.2);
        assert($ret === false);
        assert($conn->errCode == SOCKET_ETIMEDOUT);
    });
    swoole_event_wait();
    $pm->kill();
};

$pm->childFunc = function () use ($pm, $port)
{

    $serv = new \swoole_server('127.0.0.1', $port, SWOOLE_BASE);
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
