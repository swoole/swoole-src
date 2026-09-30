--TEST--
swoole_client_sync: a persistent connection that timed out is not reused
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$pm = new ProcessManager;

$pm->parentFunc = function () use ($pm) {
    $client1 = new Swoole\Client(SWOOLE_SOCK_TCP | SWOOLE_KEEP | SWOOLE_SYNC);
    Assert::true($client1->connect(TCP_SERVER_HOST, $pm->getFreePort(), 0.05));
    Assert::same($client1->send('hello'), 5);
    Assert::false(@$client1->recv());
    Assert::same($client1->errCode, SOCKET_EAGAIN);
    Assert::true($client1->close());

    $client2 = new Swoole\Client(SWOOLE_SOCK_TCP | SWOOLE_KEEP | SWOOLE_SYNC);
    Assert::true($client2->connect(TCP_SERVER_HOST, $pm->getFreePort(), 0.5));
    Assert::false($client2->reuse);
    $client2->close(true);

    $pm->kill();
};

$pm->childFunc = function () use ($pm) {
    $server = new Swoole\Server(TCP_SERVER_HOST, $pm->getFreePort(), SWOOLE_BASE);
    $server->set([
        'worker_num' => 1,
        'log_file' => '/dev/null',
    ]);
    $server->on('WorkerStart', function () use ($pm) {
        $pm->wakeup();
    });
    $server->on('Receive', function () {
    });
    $server->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
