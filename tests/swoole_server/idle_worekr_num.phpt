--TEST--
swoole_server: idle_worker_num
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
$pm = new SwooleTest\ProcessManager;

use Swoole\Server;
use Swoole\Client;

$counter = new Swoole\Atomic(0);

$pm->parentFunc = function ($pid) use ($pm) {
    $client = new Client(SWOOLE_SOCK_TCP, SWOOLE_SOCK_SYNC);
    if (!$client->connect('127.0.0.1', $pm->getFreePort())) {
        exit("connect failed\n");
    }
    $client->send("hello world");
    $data = $client->recv();
    Assert::assert($data);
    $json = json_decode($data);
    Assert::eq($json->idle_worker_num, 2);
    $pm->kill();
};

$pm->childFunc = function () use ($pm, $counter) {
    $serv = new Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE, SWOOLE_SOCK_TCP);
    $serv->set([
        'worker_num' => 3,
        'log_level' => SWOOLE_LOG_ERROR,
        'enable_coroutine' => false,
    ]);
    $serv->on("workerStart", function (Server $serv, $wid) use ($pm, $counter) {
        if ($counter->add(1) == $serv->setting['worker_num']) {
            $serv->defer(function () use ($pm) {
                $pm->wakeup();
            });
        }
    });
    $serv->on('receive', function (Server $serv, $fd, $tid, $data) {
        usleep(10000);
        $serv->send($fd, json_encode($serv->stats()));
    });
    $serv->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECTF--
