--TEST--
swoole_socket_coro: sendfile
--SKIPIF--
<?php require  __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Server;

$pm = new SwooleTest\ProcessManager;
$pm->parentFunc = function ($pid) use ($pm)
{
    Co\Run(function ()  use ($pm) {
        $conn = new Swoole\Coroutine\Socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
        Assert::assert($conn->connect('127.0.0.1', $pm->getFreePort()));

        $conn->send(pack('N', filesize(TEST_IMAGE)));
        $ret = $conn->sendfile(TEST_IMAGE);
        Assert::assert($ret);

        $data = $conn->recv();
        $conn->send(pack('N', 8) . 'shutdown');
        $conn->close();
        Assert::same($data, md5_file(TEST_IMAGE));
    });
};

$pm->childFunc = function () use ($pm)
{
    $serv = new Server(TCP_SERVER_HOST, $pm->getFreePort(), SWOOLE_BASE, SWOOLE_SOCK_TCP);
    $serv->set([
        "worker_num" => 1,
        'log_file' => '/dev/null',
        'open_length_check' => true,
        'dispatch_mode' => 1,
        'package_length_type' => 'N',
        'package_length_offset' => 0,
        'package_body_offset' => 4,
        'package_max_length' => 2000000,
    ]);
    $serv->on("WorkerStart", function (Server $serv)  use ($pm)
    {
        $pm->wakeup();
    });
    $serv->on("Receive", function (Server $serv, $fd, $rid, $data)
    {
        if (substr($data, 4, 8) == 'shutdown')
        {
            $serv->shutdown();
            return;
        }
        $serv->send($fd, md5(substr($data, 4)));
    });
    $serv->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
