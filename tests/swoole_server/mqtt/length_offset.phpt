--TEST--
swoole_server/mqtt: length_offset
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

use SwooleTest\MQTT\Helper;

$pm = new SwooleTest\ProcessManager;
$pm->parentFunc = function () use ($pm) {
    Co\run(function () use ($pm) {
        $client = new Co\Client(SWOOLE_SOCK_TCP);
        Assert::assert($client->connect('127.0.0.1', $pm->getFreePort()));
        Assert::assert($client->send(Helper::encodePublish([
            'cmd' => 3,
            'topic' => 'swoole/mqtt/test',
            'content' => '{"name":"swoole", "type":"mqtt", "data":'. str_repeat("swoole", 100) .'}']))
        );
        echo $client->recv();
        $client->close();
        $pm->kill();
    });
};
$pm->childFunc = function () use ($pm) {
    $server = new Swoole\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $server->set([
        'worker_num' => 1,
        'open_mqtt_protocol' => 1,
    ]);

    $server->on('receive', function (Swoole\Server $serv, int $fd, int $rid, string $data) {
        $header = Helper::getHeader($data);
        Assert::eq($header['type'], 3);
        Assert::eq(strlen($data), 662);
        $serv->send($fd, strlen($data));
    });

    $server->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
662
