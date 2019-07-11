--TEST--
swoole_websocket_server: websocket server disconnect
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
$pm = new ProcessManager;
$pm->parentFunc = function (int $pid) use ($pm) {
    $cli = new SwooleTest\Samtleben\WebsocketClient;
    $connected = $cli->connect('127.0.0.1', $pm->getFreePort(), '/');
    Assert::assert($connected);
    $response = $cli->sendRecv("shutdown");
    echo unpack('n', substr($response, 0, 2))[1] . "\n";
    echo substr($response, 2) . "\n";
    $pm->kill();
};
$pm->childFunc = function () use ($pm) {
    $serv = new swoole_websocket_server('127.0.0.1', $pm->getFreePort(), SERVER_MODE_RANDOM);
    $serv->set([
        // 'worker_num' => 1,
        'log_file' => '/dev/null'
    ]);
    $serv->on('WorkerStart', function () use ($pm) {
        $pm->wakeup();
    });
    $serv->on('Message', function (swoole_websocket_server $serv, swoole_websocket_frame $frame) {
        if ($frame->data == 'shutdown') {
            $serv->disconnect($frame->fd, 4000, 'shutdown received');
        }
    });
    $serv->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
4000
shutdown received
