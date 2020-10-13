--TEST--
swoole_server/mqtt: send_big_pack
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
        $client->set(['open_mqtt_protocol' => true, 'package_max_length' => 5 * 1024 *1024]);
        Assert::assert($client->connect('127.0.0.1', $pm->getFreePort()));
        Assert::assert($client->send(Helper::encodePublish([
            'cmd' => 3,
            'topic' => 'swoole/mqtt/test',
            'content' => '{"name":"swoole", "type":"mqtt", "data":'. str_repeat("sw", 2 * 1024 * 1024 ) .'}']))
        );
        var_dump(Helper::getHeader($client->recv()));
        $client->close();
        $pm->kill();
    });
};
$pm->childFunc = function () use ($pm) {
    $server = new Swoole\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $server->set([
        'worker_num' => 1,
        'open_mqtt_protocol' => 1,
        'package_max_length' => 5 * 1024 *1024
    ]);

    $server->on('receive', function (Swoole\Server $serv, int $fd, int $rid, string $data) {
        $header = Helper::getHeader($data);
        Assert::eq($header['type'], 3);
        Assert::eq(strlen($data), 4194368);
        $serv->send($fd, Helper::encodePing(13));
    });

    $server->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
array(4) {
  ["type"]=>
  int(13)
  ["dup"]=>
  int(0)
  ["qos"]=>
  int(0)
  ["retain"]=>
  int(0)
}
