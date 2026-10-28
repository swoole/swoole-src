--TEST--
swoole_client_sync: udp sync client sendto
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$pm = new ProcessManager;
$pm->parentFunc = function () use ($pm) {
    $client = new Swoole\Client(SWOOLE_SOCK_UDP);
    Assert::true($client->connect('127.0.0.1', $pm->getFreePort()));
    Assert::true($client->sendto('127.0.0.1', $pm->getFreePort(), 'TestUdpClientSendto'));
    echo 'FromServer:', $client->recv(), "\n";
    $client->close();
    $pm->kill();
    echo 'SUCCESS';
};
$pm->childFunc = function () use ($pm) {
    $server = new Swoole\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE, SWOOLE_SOCK_UDP);
    $server->set(['worker_num' => 1, 'log_file' => '/dev/null']);
    $server->on('workerStart', function () use ($pm) { $pm->wakeup(); });
    $server->on('packet', function ($server, $data, $client) {
        $server->sendto($client['address'], $client['port'], $data);
    });
    $server->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
FromServer:TestUdpClientSendto
SUCCESS
