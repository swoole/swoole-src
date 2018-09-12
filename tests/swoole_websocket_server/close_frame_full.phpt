--TEST--
swoole_websocket_server: websocket server send and recv close frame full test
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require_once __DIR__ . '/../include/bootstrap.php';
include __DIR__ . "/../include/lib/class.websocket_client.php";
$pm = new ProcessManager;
$pm->parentFunc = function (int $pid) use ($pm) {
    go(function () use ($pm) {
        for ($i = 1000; $i--;) {
            $cli = new \Swoole\Coroutine\Http\Client('127.0.0.1', $pm->getFreePort());
            $cli->set(['timeout' => 1]);
            $ret = $cli->upgrade('/');
            assert($ret);
            $code = mt_rand(0, 5000);
            $reason = md5($code);
            $close_frame = new swoole_websocket_close_frame;
            $close_frame->code = $code;
            $close_frame->reason = $reason;
            $cli->push($close_frame);
            // recv the last close frame
            $frame = $cli->recv();
            assert($frame instanceof swoole_websocket_close_frame);
            assert($frame->opcode = WEBSOCKET_OPCODE_CLOSE);
            assert(md5($frame->code) === $frame->reason);
            // connection closed
            assert($cli->recv() === false);
            assert($cli->connected === false);
            assert($cli->errCode === 0); // connection close normally
        }
    });
    swoole_event_wait();
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
        assert($frame instanceof swoole_websocket_close_frame);
        assert($frame->opcode = WEBSOCKET_OPCODE_CLOSE);
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
