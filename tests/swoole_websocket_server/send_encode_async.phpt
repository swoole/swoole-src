--TEST--
swoole_websocket_server: websocket server full test
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require_once __DIR__ . '/../include/bootstrap.php';
include __DIR__ . "/../include/lib/class.websocket_client.php";
$data_list = [];
for ($i = MAX_REQUESTS; $i--;) {
    $rand = openssl_random_pseudo_bytes(mt_rand(1, 128000));
    if (mt_rand(0, 1)) {
        $data_list[$i] = $i . '|' . WEBSOCKET_OPCODE_BINARY . '|' . $rand;
    } else {
        $data_list[$i] = $i . '|' . WEBSOCKET_OPCODE_TEXT . '|' . base64_encode($rand);
    }
}
$pm = new ProcessManager;
$pm->parentFunc = function (int $pid) use ($pm, $data_list) {
    $clients = [];
    for ($c = MAX_CONCURRENCY_LOW; $c--;) {
        $cli = new swoole_http_client('127.0.0.1', $pm->getFreePort());
        $cli->set(['timeout' => -1]);
        global $data_list;
        $cli->data_list = $data_list;
        $cli->on('message', function ($_cli, $frame) {
            list($id, $opcode) = explode('|', $frame->data, 3);
            assert($frame->finish);
            assert($frame->opcode === (int)$opcode);
            assert($frame->data === $_cli->data_list[$id]);
            unset($_cli->data_list[$id]);
            if (empty($_cli->data_list)) {
                $_cli->close();
            }
        });

        $ret = $cli->upgrade('/', function ($cli) {

        });
        if ($ret == false) {
            die("error=" . $cli->errCode);
        }
        $clients[] = $cli;
    }
    swoole_event_wait();
    $pm->kill();
};
$pm->childFunc = function () use ($pm) {
    $serv = new swoole_websocket_server('127.0.0.1', $pm->getFreePort(), mt_rand(0, 1) ? SWOOLE_BASE : SWOOLE_PROCESS);
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
            if (!assert($ret)) {
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
