--TEST--
swoole_server_port: heartbeat 3
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc';
skip_if_darwin_todo();
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine\Client;
use Swoole\Coroutine\Channel;
use Swoole\Server;

use function Swoole\Coroutine\go;
use function Swoole\Coroutine\run;

$pm = new ProcessManager();
$pm->initFreePorts(3);

$pm->parentFunc = function ($pid) use ($pm) {
    run(function () use ($pm) {
        $closed = new Channel(1);
        go(function () use ($pm, $closed) {
            $cli = new Client(SWOOLE_SOCK_TCP);
            Assert::true($cli->connect('127.0.0.1', $pm->getFreePort(0)));
            Assert::true($closed->pop(6));
            Assert::same($cli->send('ping'), 4);
            Assert::same($cli->recv(2), 'ok');
            $cli->close();
            echo "DONE 0\n";
        });
        go(function () use ($pm, $closed) {
            $cli = new Client(SWOOLE_SOCK_TCP);
            Assert::true($cli->connect('127.0.0.1', $pm->getFreePort(1)));
            Assert::same($cli->recv(5), '');
            $cli->close();
            echo "DONE 1\n";
            $closed->push(true);
        });
    });
    $pm->kill();
};

$pm->childFunc = function () use ($pm) {
    $server = new Server('127.0.0.1', $pm->getFreePort(0), SWOOLE_BASE);
    $server->on('receive', function ($server, $fd, $reactorId, $data) {
        $server->send($fd, 'ok');
    });
    $server->on('WorkerStart', function (Server $serv) use ($pm) {
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
