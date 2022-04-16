--TEST--
swoole_client_sync: recv timeout
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
$pm = new ProcessManager;

$pm->parentFunc = function ($pid) use ($pm) {
    $client = new Swoole\Client(SWOOLE_SOCK_TCP, SWOOLE_SOCK_SYNC);
    $r = $client->connect(TCP_SERVER_HOST, $pm->getFreePort(), 0.5);
    Assert::assert($r);
    $client->send(pack('N', filesize(TEST_IMAGE)));
    $data = @$client->recv();
    Assert::false($data);
    Assert::same($client->errCode, SOCKET_EAGAIN);
    $client->close();
    $pm->kill();
};

$pm->childFunc = function () use ($pm) {
    $serv = new Swoole\Server(TCP_SERVER_HOST, $pm->getFreePort(), SWOOLE_BASE, SWOOLE_SOCK_TCP);
    $serv->set([
        "worker_num" => 1,
        'log_file' => '/dev/null',
    ]);
    $serv->on("WorkerStart", function (Swoole\Server $serv) use ($pm) {
        $pm->wakeup();
    });
    $serv->on("Receive", function (Swoole\Server $serv, $fd, $rid, $data) {
        //do nothing
    });
    $serv->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
