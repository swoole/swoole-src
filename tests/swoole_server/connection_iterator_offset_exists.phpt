--TEST--
swoole_server: connection iterator offsetExists
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Server;

$pm = new SwooleTest\ProcessManager;

$pm->parentFunc = function ($pid) use ($pm) {
    go(function () use ($pm) {
        $client = new Swoole\Coroutine\Client(SWOOLE_SOCK_TCP);
        Assert::true($client->connect('127.0.0.1', $pm->getFreePort()));
        Assert::same($client->recv(), "OK");
        $client->close();
    });
    Swoole\Event::wait();
    $pm->kill();
};

$pm->childFunc = function () use ($pm) {
    $serv = new Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $serv->set([
        'worker_num' => 1,
        'log_file' => '/dev/null',
    ]);
    $serv->on('WorkerStart', function (Server $serv) use ($pm) {
        $pm->wakeup();
    });
    $serv->on('connect', function (Server $serv, int $fd) {
        Assert::true(isset($serv->connections[$fd]));
        Assert::false(isset($serv->connections[$fd + 100000]));
        $serv->send($fd, "OK");
    });
    $serv->on('receive', function (Server $serv, int $fd, int $reactor_id, string $data) {
    });
    $serv->start();
};

$pm->childFirst();
$pm->run();
echo "DONE\n";
?>
--EXPECT--
DONE
