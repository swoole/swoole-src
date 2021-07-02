--TEST--
swoole_server_port: heartbeat 3
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
$pm->initFreePorts(3);

$pm->parentFunc = function ($pid) use ($pm) {
    run(function () use ($pm) {
        $test_func = function ($port_index, $sleep_seconds) use ($pm) {
            $cli = new Swoole\Coroutine\Client(SWOOLE_SOCK_TCP);
            $cli->connect('127.0.0.1', $pm->getFreePort($port_index));
            System::sleep($sleep_seconds);
            return $cli->recv(0.01);
        };
        go(function () use ($test_func) {
            Assert::same($test_func(0, 3), false);
            echo "DONE 0\n";
        });
        go(function () use ($test_func) {
            Assert::same($test_func(1, 2.3), '');
            echo "DONE 1\n";
        });
    });
    $pm->kill();
};

$pm->childFunc = function () use ($pm)
{
    $server = new swoole_server('127.0.0.1', $pm->getFreePort(0), SWOOLE_BASE);
    $server->on('receive', function ($server, $fd, $reactorId, $data) {
        $server->send($fd, 'ok');
    });
    $server->on("WorkerStart", function (Server $serv) use ($pm) {
        $pm->wakeup();
    });

    $port2 = $server->listen('127.0.0.1', $pm->getFreePort(1), SWOOLE_SOCK_TCP);
    $port2->set([
        'heartbeat_idle_time' => 2,
    ]);

    $server->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE 1
DONE 0
