--TEST--
swoole_server_port: heartbeat 1
--SKIPIF--
<?php require  __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use function Swoole\Coroutine\go;
use function Swoole\Coroutine\run;
use Swoole\Coroutine\System;
use Swoole\Server;

$pm = new ProcessManager;
$pm->initFreePorts(2);

$pm->parentFunc = function ($pid) use ($pm)
{
    run(function () use ($pm) {
        go(function () use ($pm) {
            $cli = new Swoole\Coroutine\Client(SWOOLE_SOCK_TCP);
            $cli->connect('127.0.0.1', $pm->getFreePort(0));
            for ($i = 0; $i < 2; ++$i) {
                $cli->send('hello');
                $data = $cli->recv();
                if ($data != 'ok') {
                    echo "ERROR\n";
                }
                System::sleep(2);
            }
            System::sleep(3);
            $cli->send('hello');
            $data = $cli->recv();
            if ($data == 'ok') {
                echo "ERROR\n";
            }
        });

        go(function () use ($pm) {
            $cli = new Swoole\Coroutine\Client(SWOOLE_SOCK_TCP);
            $cli->connect('127.0.0.1', $pm->getFreePort(1));
            for ($i = 0; $i < 2; ++$i) {
                $cli->send('hello');
                $data = $cli->recv();
                if ($data != 'ok') {
                    echo "ERROR\n";
                }
                System::sleep(2);
            }
            System::sleep(3);
            $cli->send('hello');
            $data = $cli->recv();
            if ($data == 'ok') {
                echo "ERROR\n";
            } else {
                echo "OK";
            }
        });
    });
    $pm->kill();
};

$pm->childFunc = function () use ($pm)
{
    $server = new Server('127.0.0.1', $pm->getFreePort(0), SWOOLE_BASE);
    $server->set([
        'heartbeat_check_interval' => 1,
        'heartbeat_idle_time' => 3
    ]);
    $server->on('receive', function (Server $server, $fd, $reactorId, $data) {
        $server->send($fd, 'ok');
    });
    $server->on("WorkerStart", function (Server $serv) use ($pm) {
        $pm->wakeup();
    });

    $port2 = $server->listen('127.0.0.1', $pm->getFreePort(1), SWOOLE_SOCK_TCP);
    // $port2->set([
        // 'heartbeat_check_interval' => 1,
        // 'heartbeat_idle_time' => 5
    // ]);
    $port2->on('receive', function (Server $server, $fd, $reactorId, $data) {
        $server->send($fd, 'ok');
    });

    $server->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
OK
