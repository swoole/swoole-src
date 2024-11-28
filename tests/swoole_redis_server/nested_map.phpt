--TEST--
swoole_redis_server: nested map
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Redis\Server;

define("UUID", uniqid());
define("NUMBER", random_int(1, 1000000));

$pm = new ProcessManager;
$pm->parentFunc = function ($pid) use ($pm) {
    $redis = new Predis\Client('tcp://127.0.0.1:' . $pm->getFreePort());
    $map = $redis->get('map');
    Assert::notEmpty($map);
    Assert::eq($map[0], 'uuid');
    Assert::eq($map[1], UUID);
    Assert::isArray($map[3]);
    Assert::eq($map[5], NUMBER);
    Assert::eq($map[3][1], NUMBER);
    Assert::eq($map[3][2], UUID);

    $set = $redis->get('set');
    Assert::notEmpty($set);
    Assert::eq($set[0], UUID);
    Assert::isArray($set[1]);
    Assert::eq($set[2], NUMBER);
    Assert::eq($set[1][1], NUMBER);
    Assert::eq($set[1][3], UUID);

    $pm->kill();
};

$pm->childFunc = function () use ($pm) {
    $server = new Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $server->setHandler('GET', function ($fd, $data) use ($server) {
        $key = $data[0];
        if ($key == 'map') {
            $out = Server::format(Server::MAP, [
                'uuid' => UUID,
                'list' => [1, NUMBER, UUID],
                'number' => NUMBER,
            ]);
        } elseif ($key == 'set') {
            $out = Server::format(Server::SET, [
                UUID,
                ['number' => NUMBER, 'uuid' => UUID],
                NUMBER,
            ]);
        } else {
            $out = Server::format(Server::ERROR, 'bad key');
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
