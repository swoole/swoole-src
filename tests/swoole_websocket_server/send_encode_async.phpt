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
        go(function () use ($pm) {
            $cli = new Co\http\client('127.0.0.1', $pm->getFreePort());
            $cli->set(['timeout' => -1]);
            $ret = $cli->upgrade('/');
            if ($ret == false) {
                die("error=" . $cli->errCode);
            }
            global $data_list;
            $cli_data_list = $data_list;

            while (true) {
                $frame = $cli->recv();
                list($id, $opcode) = explode('|', $frame->data, 3);
                Assert::assert($frame->finish);
                Assert::same($frame->opcode, (int)$opcode);
                Assert::same($frame->data, $cli_data_list[$id]);
                unset($cli_data_list[$id]);
                if (empty($cli_data_list)) {
                    break;
                }
            }
            $cli->close();
        });
    }
    swoole_event_wait();
    $pm->kill();
};

$pm->childFunc = function () use ($pm) {
    $serv = new swoole_websocket_server('127.0.0.1', $pm->getFreePort(), SERVER_MODE_RANDOM);
    $serv->set([
        'worker_num' => 1,
        'log_file' => TEST_LOG_FILE,
        'send_yield' => true,
        'send_timeout' => 2,
    ]);
    $serv->on('workerStart', function () use ($pm) {
        $pm->wakeup();
    });
    $serv->on('open', function (swoole_websocket_server $serv, swoole_http_request $req) {
        global $data_list;
        foreach ($data_list as $data) {
            $opcode = (int)explode('|', $data, 3)[1];
            if (mt_rand(0, 1)) {
                $frame = new swoole_websocket_frame;
                $frame->opcode = $opcode;
                $frame->data = $data;
                $ret = $serv->push($req->fd, $frame);
            } else {
                $ret = $serv->push($req->fd, $data, $opcode);
            }
            if (!Assert::assert($ret)) {
                var_dump($serv->getLastError());
            }
        }
    });
    $serv->on('message', function (swoole_websocket_server $serv, swoole_websocket_frame $frame) { });
    $serv->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
