--TEST--
swoole_websocket_server: websocket server full test
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
$data_list = [];
for ($i = MAX_REQUESTS; $i--;) {
    $rand = get_safe_random(mt_rand(1, 128000));
    if (mt_rand(0, 1)) {
        $data_list[$i] = $i . '|' . WEBSOCKET_OPCODE_BINARY . '|' . $rand;
    } else {
        $data_list[$i] = $i . '|' . WEBSOCKET_OPCODE_TEXT . '|' . base64_encode($rand);
    }
}
$pm = new ProcessManager;
$pm->parentFunc = function (int $pid) use ($pm, $data_list) {
    for ($c = MAX_CONCURRENCY_LOW; $c--;) {
        go(function () use ($pm, $data_list) {
            $cli = new \Swoole\Coroutine\Http\Client('127.0.0.1', $pm->getFreePort());
            $cli->set(['timeout' => 5]);
            $ret = $cli->upgrade('/');
            Assert::assert($ret);
            foreach ($data_list as $data) {
                if (mt_rand(0, 1)) {
                    $frame = new swoole_websocket_frame;
                    $frame->opcode = (int)explode('|', $data, 3)[1];
                    $frame->data = $data;
                    $ret = $cli->push($frame);
                } else {
                    $ret = $cli->push($data, (int)explode('|', $data, 3)[1]);
                }
                if (!Assert::assert($ret)) {
                    var_dump(swoole_strerror(swoole_last_error()));
                } else {
                    $ret = $cli->recv();
                    unset($data_list[$ret->data]);
                }
            }
            Assert::assert(empty($data_list));
        });
    }
    swoole_event_wait();
    $pm->kill();
};
$pm->childFunc = function () use ($pm) {
    $serv = new swoole_websocket_server('127.0.0.1', $pm->getFreePort(), SERVER_MODE_RANDOM);
    $serv->set([
        // 'worker_num' => 1,
        'log_file' => '/dev/null'
    ]);
    $serv->on('workerStart', function () use ($pm) {
        $pm->wakeup();
    });
    $serv->on('message', function (swoole_websocket_server $serv, swoole_websocket_frame $recv_frame) {
        global $data_list;
        list($id, $opcode) = explode('|', $recv_frame->data, 3);
        if (!Assert::assert($recv_frame->finish)) {
            return;
        }
        if (!Assert::assert($recv_frame->opcode === (int)$opcode)) {
            return;
        }
        if (!Assert::assert($recv_frame->data === $data_list[$id])) {
            var_dump($recv_frame->data);
            var_dump($data_list[$id]);
            return;
        }
        if (mt_rand(0, 1)) {
            $send_frame = new swoole_websocket_frame;
            $send_frame->data = $id;
            $serv->push($recv_frame->fd, $send_frame);
        } else {
            $serv->push($recv_frame->fd, $id);
        }
    });
    $serv->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
