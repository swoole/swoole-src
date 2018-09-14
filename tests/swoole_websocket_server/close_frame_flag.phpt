--TEST--
swoole_websocket_server: websocket server active close with close frame flag false
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
    $cli->sendRecv('shutdown');
    $pm->kill();
};
$pm->childFunc = function () use ($pm) {
    $serv = new swoole_websocket_server('127.0.0.1', $pm->getFreePort(), mt_rand(0, 1) ? SWOOLE_BASE : SWOOLE_PROCESS);
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
            assert(false); // Should never reach here
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