--TEST--
swoole_redis_server: empty
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Redis\Server;

$pm = new ProcessManager;
$pm->parentFunc = function ($pid) use ($pm) {
    $redis = new Predis\Client('tcp://127.0.0.1:' . $pm->getFreePort());
    $map = $redis->get('map');
    Assert::eq($map, [0, '', false, null]);
    $pm->kill();
};

$pm->childFunc = function () use ($pm) {
    $server = new Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $server->setHandler('GET', function ($fd, $data) use ($server) {
        $server->send($fd, Server::format(Server::SET, [0, '', false, null]));
    });
    $server->on('WorkerStart', function ($server) use ($pm) {
        $pm->wakeup();
    });
    $server->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
