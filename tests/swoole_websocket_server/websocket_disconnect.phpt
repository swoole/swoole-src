--TEST--
swoole_websocket_server: websocket server disconnect
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>

--INI--
assert.active=1
assert.warning=1
assert.bail=0
assert.quiet_eval=0

--FILE--
<?php
require_once __DIR__ . '/../include/bootstrap.php';
include __DIR__ . "/../include/lib/class.websocket_client.php";
$pm = new ProcessManager;
$pm->parentFunc = function (int $pid) use ($pm) {
    $cli = new WebsocketClient;
    $connected = $cli->connect('127.0.0.1', $pm->getFreePort(), '/');
    assert($connected);
    $response = $cli->sendRecv("shutdown");
    $byteArray = unpack('C*', $response);
    assert($byteArray[1] == 0x0F);    // Test Status Code bit 1 = 15
    assert($byteArray[2] == 0xA0);  // Test Status Code bit 2 = 160
    echo $byteArray[1] . "\n";
    echo $byteArray[2] . "\n";
    echo substr($response, 2);
    $pm->kill();
};
$pm->childFunc = function () use ($pm) {
    $serv = new swoole_websocket_server('127.0.0.1', $pm->getFreePort());
    $serv->set([
        'worker_num' => 1,
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
15
160
shutdown received
