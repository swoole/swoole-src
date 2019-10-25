--TEST--
swoole_socket_coro: reuse socket object [2]
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

const SEND_STR = "hello world\n";

use SwooleTest\ProcessManager;
use Swoole\Constant;
use Swoole\Server;

$pm = new ProcessManager;

$pm->initFreePorts(2);

$pm->parentFunc = function ($pid) use ($pm) {

    $map = [];

    $serv = new Server('127.0.0.1', $pm->getFreePort(1), SWOOLE_BASE);

    $serv->on(Constant::EVENT_WORKER_START, function (Server $server)  use ($pm, &$map) {
        $socket = new Swoole\Coroutine\Socket(AF_INET, SOCK_STREAM, 0);
        Assert::assert($socket->connect('127.0.0.1', $pm->getFreePort()));
        Assert::assert($socket->send(SEND_STR));
        echo $socket->recv();
        $map['sock'] = $socket;

        $server->shutdown();
    });

    $serv->on(Constant::EVENT_RECEIVE, function () {

    });

    echo "Server start [1]\n";
    $serv->start();
    echo "Server stop [1]\n";

    echo "Co [2]\n";

    Co\Run(function () use ($pm, &$map) {
        $socket = $map['sock'];
        Assert::assert($socket->send(SEND_STR));
        echo $socket->recv();
        unset($map['sock']);
    });
};

$pm->childFunc = function () use ($pm) {
    $socket = new Swoole\Coroutine\Socket(AF_INET, SOCK_STREAM, 0);
    Assert::assert($socket->bind('127.0.0.1', $pm->getFreePort()));
    Assert::assert($socket->listen(128));
    $pm->wakeup();
    go(function () use ($socket, $pm) {
        $client = null;
        while (true) {
            $client = $socket->accept();
            if ($client) {
                break;
            }
        }
        Assert::isInstanceOf($client, Swoole\Coroutine\Socket::class);
        while (true) {
            $client_data = $client->recv(1024, -1);
            if (empty($client_data)) {
                echo "closed\n";
                break;
            }
            if ($client->errCode > 0) {
                Assert::same($client->errCode, SOCKET_ETIMEDOUT);
                break;
            } else {
                Assert::same($client_data, SEND_STR);
                $client->send('swoole '.SEND_STR);
            }
        }
        $client->close();
        $socket->close();
        echo "server exit\n";
    });
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
Server start [1]
swoole hello world
Server stop [1]
Co [2]
swoole hello world
closed
server exit
