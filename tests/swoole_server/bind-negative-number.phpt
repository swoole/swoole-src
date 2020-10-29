--TEST--
swoole_server: bind negative number
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Server;

$pm = new SwooleTest\ProcessManager;
$pm->parentFunc = function () use ($pm) {
    $client = new Swoole\Client(SWOOLE_SOCK_TCP);
    if (!$client->connect('127.0.0.1', $pm->getFreePort())) {
        exit("connect failed. Error: {$client->errCode}\n");
    }
    $client->send("hello world\n");
    $pm->kill();
};
$pm->childFunc = function () use ($pm) {
    $server = new Server('127.0.0.1', $pm->getFreePort());
    $server->set([
        'worker_num' => 2,
        'dispatch_mode' => 5, //uid dispatch
    ]);
    $server->on("workerStart", function ($serv) use ($pm) {
        $pm->wakeup();
    });
    $server->on('receive', function (Swoole\Server $server, $fd, $reactor_id, $data) {
        $status = $server->bind($fd, -1);
        Assert::false($status);
    });
    $server->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
Warning: Swoole\Server::bind(): uid can not be greater than 4294967295 or less than 0 in %s on line %d
[%s]	INFO	Server is shutdown now
