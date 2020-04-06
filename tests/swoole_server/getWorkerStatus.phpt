--TEST--
swoole_server: getWorkerStatus
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$pm = new SwooleTest\ProcessManager;
$pm->parentFunc = function () use ($pm) {
    Co\run(function () use ($pm) {
        $client = new Co\Client(SWOOLE_SOCK_TCP);
        Assert::assert($client->connect('127.0.0.1', $pm->getFreePort()));
        Assert::assert($client->send('world'));

        $data = $client->recv();
        Assert::assert($data);
        $json = json_decode($data);
        Assert::assert($json);

        Assert::eq($json->current_worker, SWOOLE_WORKER_BUSY);
        Assert::eq($json->another_worker, SWOOLE_WORKER_IDLE);

        $pm->kill();
    });
};
$pm->childFunc = function () use ($pm) {
    $server = new Swoole\Server('127.0.0.1', $pm->getFreePort());
    $server->set([
        'worker_num' => 2,
        'log_file' => '/dev/null'
    ]);
    $server->on('workerStart', function (Swoole\Server $serv) use ($pm) {
        $pm->wakeup();
    });

    $server->on('receive', function (Swoole\Server $serv, int $fd, int $rid, string $data) {
        $serv->send($fd, json_encode([
            'current_worker' => $serv->getWorkerStatus(), 
            'another_worker' => $serv->getWorkerStatus(1-$serv->getWorkerId()), 
        ]));
    });

    $server->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
