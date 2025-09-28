--TEST--
swoole_websocket_server: websocket server send and recv close frame full test
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
$pm = new ProcessManager;
$pm->parentFunc = function (int $pid) use ($pm) {
    for ($c = MAX_CONCURRENCY_LOW; $c--;) {
        go(function () use ($pm) {
            $cli = new \Swoole\Coroutine\Http\Client('127.0.0.1', $pm->getFreePort());
            $cli->set([
                'timeout' => 5,
                'open_websocket_ping_frame' => true,
                'open_websocket_pong_frame' => true,
                'open_websocket_close_frame' => true,
            ]);
            for ($n = MAX_REQUESTS; $n--;) {
                Assert::true($cli->upgrade('/'));
                $code = mt_rand(0, 5000);
                $reason = md5($code);
                $close_frame = new Swoole\WebSocket\CloseFrame;
                $close_frame->code = $code;
                $close_frame->reason = $reason;
                Assert::true($cli->push($close_frame));
                // recv the last close frame
                $frame = $cli->recv();
                Assert::isInstanceOf($frame, Swoole\WebSocket\CloseFrame::class);
                Assert::same($frame->opcode, WEBSOCKET_OPCODE_CLOSE);
                Assert::same(md5($frame->code), $frame->reason);
                // connection closed
                Assert::true($cli->disconnect($frame->code, $frame->reason));
                Assert::false($cli->recv());
                Assert::false($cli->connected);
                Assert::same($cli->errCode, 5001); // connection close normally
            }
        });
    }
    Swoole\Event::wait();
    $pm->kill();
};
$pm->childFunc = function () use ($pm) {
    $serv = new Swoole\WebSocket\Server('127.0.0.1', $pm->getFreePort(), SERVER_MODE_RANDOM);
    $serv->set([
        // 'worker_num' => 1,
        'log_file' => '/dev/null'
    ]);
    $serv->on('WorkerStart', function () use ($pm) {
        $pm->wakeup();
    });
    $serv->on('Message', function (Swoole\WebSocket\Server  $serv, Swoole\WebSocket\Frame $frame) {
        Assert::isInstanceOf($frame, Swoole\WebSocket\CloseFrame::class);
        Assert::same($frame->opcode, WEBSOCKET_OPCODE_CLOSE);
        if (mt_rand(0, 1)) {
            $serv->push($frame->fd, $frame);
        } else {
            $serv->disconnect($frame->fd, $frame->code, $frame->reason);
        }
    });
    $serv->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
