--TEST--
swoole_websocket_server: websocket server full test
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require_once __DIR__ . '/../include/bootstrap.php';
include __DIR__ . "/../include/lib/class.websocket_client.php";
$data_list = [];
for ($i = 10; $i--;) {
    $rand = openssl_random_pseudo_bytes(mt_rand(1, 100));
    if (mt_rand(0, 1)) {
        $data_list[$i] = $i . '|' . WEBSOCKET_OPCODE_BINARY . '|' . $rand;
    } else {
        $data_list[$i] = $i . '|' . WEBSOCKET_OPCODE_TEXT . '|' . base64_encode($rand);
    }
}
$pm = new ProcessManager;
$pm->parentFunc = function (int $pid) use ($pm, $data_list) {
    // sync
    $cli = new WebsocketClient;
    $connected = $cli->connect('127.0.0.1', $pm->getFreePort(), '/');
    assert($connected);
    while ($payload = $cli->recvData()) {
        list($id) = explode('|', $payload, 3);
        assert($payload == $data_list[$id]);
        unset($data_list[$id]);
        if (empty($data_list)) {
            break;
        }
    }
    // coroutine
    go(function () use ($pm) {
        global $data_list;
        $cli = new \Swoole\Coroutine\Http\Client('127.0.0.1', $pm->getFreePort());
        $cli->set(['timeout' => 1]);
        $ret = $cli->upgrade('/');
        assert($ret);
        while (($frame = $cli->recv(-1))) {
            /**@var $frame swoole_websocket_frame */
            list($id, $opcode) = explode('|', $frame->data, 3);
            assert($frame->finish);
            assert($frame->opcode === (int)$opcode);
            assert($frame->data === $data_list[$id]);
            unset($data_list[$id]);
            if (empty($data_list)) {
                break;
            }
        }
        assert(empty($data_list));
        $pm->kill();
    });
    swoole_event_wait();
};
$pm->childFunc = function () use ($pm) {
    $serv = new swoole_websocket_server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $serv->set([
        'worker_num' => 1,
        'log_file' => '/dev/null'
    ]);
    $serv->on('workerStart', function () use ($pm) {
        $pm->wakeup();
    });
    $serv->on('open', function (swoole_websocket_server $serv, swoole_http_request $req) {
        global $data_list;
        foreach ($data_list as $data) {
            $frame = new swoole_websocket_frame;
            $frame->opcode = (int)explode('|', $data, 3)[1]; //type
            $frame->data = $data;
            $frame->finish = true;
            $ret = $serv->push($req->fd, $frame);
            assert($ret);
        }
    });
    $serv->on('message', function (swoole_websocket_server $serv, swoole_websocket_frame $frame) { });
    $serv->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
