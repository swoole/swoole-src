--TEST--
swoole_server/mqtt: recv_fail
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
        $client->set(['open_mqtt_protocol' => true]);
        Assert::assert($client->connect('127.0.0.1', $pm->getFreePort()));
        $buffer = Helper::encodePing(12); // PINGREQ
//        $client->send($buffer);
        $client->send($buffer[0]);
        sleep(1);
        $client->send($buffer[1]);
        $response = $client->recv();
        $header = Helper::getHeader($response);
        var_dump($header);
        Assert::eq($header['type'], 13); // PINGRESP
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
        Assert::eq($header['type'], 12);
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
