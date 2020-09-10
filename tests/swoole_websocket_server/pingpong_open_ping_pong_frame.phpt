--TEST--
swoole_websocket_server: websocket ping pong (auto)
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
$pm = new ProcessManager;
$pm->parentFunc = function (int $pid) use ($pm) {
    go(function () use ($pm) {
        $cli = new \Swoole\Coroutine\Http\Client('127.0.0.1', $pm->getFreePort());
        $cli->set(['timeout' => 5]);
        $ret = $cli->upgrade('/');
        Assert::assert($ret);
        for ($i = 100; $i--;) {
            $ping = new swoole_websocket_frame;
            $ping->opcode = WEBSOCKET_OPCODE_PING;
            $ping->data = 'ping';
            $ret = $cli->push($ping);
            Assert::assert($ret);
            $pong = $cli->recv();
            Assert::same($pong->opcode, WEBSOCKET_OPCODE_PONG);
            Assert::same($pong->data, 'pong');
        }
        $pm->kill();
    });
    swoole_event_wait();
};
$pm->childFunc = function () use ($pm) {
    $serv = new swoole_websocket_server('127.0.0.1', $pm->getFreePort(), SERVER_MODE_RANDOM);
    $serv->set([
        // 'worker_num' => 1,
        'log_file' => '/dev/null',
        'open_websocket_ping_frame' => true,
        'open_websocket_pong_frame' => true,
    ]);
    $serv->on('workerStart', function () use ($pm) {
        $pm->wakeup();
    });
    $serv->on('open', function ($swoole_server, $req) {
    });
    $atomic = new Swoole\Atomic;
    $serv->on('message', function (swoole_websocket_server $server, swoole_websocket_frame $frame) use ($atomic) {
        if ($frame->opcode === WEBSOCKET_OPCODE_PING) {
            Assert::same($frame->data, 'ping');
            $atomic->add();
            $pongFrame = new swoole_websocket_frame;
            $pongFrame->opcode = WEBSOCKET_OPCODE_PONG;
            $pongFrame->data = 'pong';
            $server->push($frame->fd, $pongFrame);
        }
    });
    $serv->on('close', function ($swoole_server, $fd) {
    });
    $serv->start();
    Assert::same($atomic->get(), 100);
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
