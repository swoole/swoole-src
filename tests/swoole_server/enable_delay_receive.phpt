--TEST--
swoole_server: enable_delay_receive
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
        $s = microtime(true);
        Assert::eq($client->recv(), "hello world");
        time_approximate(0.3, microtime(true) - $s);
        $pm->kill();
    });
};
$pm->childFunc = function () use ($pm) {
    $server = new Swoole\Server('127.0.0.1', $pm->getFreePort());
    $server->set([
        'worker_num' => 1,
        'enable_delay_receive' => true,
        'log_file' => '/dev/null'
    ]);
    $server->on('workerStart', function (Swoole\Server $serv) use ($pm) {
        $pm->wakeup();
    });

    $server->on('connect', function (Swoole\Server $serv, int $fd, int $rid) {
        Co::sleep(0.3);
        $serv->confirm($fd);
    });
    
    $server->on('receive', function (Swoole\Server $serv, int $fd, int $rid, string $data) {
        $serv->send($fd, "hello {$data}");
    });

    $server->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECTF--
