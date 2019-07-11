--TEST--
swoole_websocket_server: websocket server active close with close frame flag false
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
    $cli->sendRecv('shutdown');
    $pm->kill();
};
$pm->childFunc = function () use ($pm) {
    $serv = new swoole_websocket_server('127.0.0.1', $pm->getFreePort(), SERVER_MODE_RANDOM);
    $serv->set([
        // 'worker_num' => 1,
        'log_file' => '/dev/null',
        'open_websocket_close_frame' => false
    ]);
    $serv->on('WorkerStart', function () use ($pm) {
        $pm->wakeup();
    });
    $serv->on('Message', function ($serv, $frame) {
        if ($frame->opcode == WEBSOCKET_OPCODE_CLOSE) {
            echo "{$frame->code}\n";
            echo "{$frame->reason}\n";
            Assert::true(false, 'never here'); // Should never reach here
        } else {
            if ($frame->data == 'shutdown') {
                echo "{$frame->data}";
                $serv->disconnect($frame->fd, 4000, 'shutdown received');
            }
        }
    });
    $serv->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
shutdown
