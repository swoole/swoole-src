--TEST--
swoole_redis_server: large data map
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Redis\Server;

define("N", random_int(1000, 1000000));

$pm = new ProcessManager;
$pm->parentFunc = function ($pid) use ($pm) {
    $redis = new Predis\Client('tcp://127.0.0.1:' . $pm->getFreePort());
    $map = $redis->get('map');
    Assert::notEmpty($map);

    $pm->kill();
};

$pm->childFunc = function () use ($pm) {
    $server = new Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $server->setHandler('GET', function ($fd, $data) use ($server) {
        $key = $data[0];
        if ($key == 'map') {
            $out = Server::format(Server::MAP, ['a' => str_repeat('a', N), 'b' => str_repeat('b', N * 3)]);
        }
        $server->send($fd, $out);
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
