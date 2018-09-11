--TEST--
swoole_websocket_server: websocket server full test
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require_once __DIR__ . '/../include/bootstrap.php';
$data_list = [];
for ($i = 100; $i--;) {
    $rand = openssl_random_pseudo_bytes(mt_rand(1, 65535));
    if (mt_rand(0, 1)) {
        $data_list[$i] = $i . '|' . WEBSOCKET_OPCODE_BINARY . '|' . $rand;
    } else {
        $data_list[$i] = $i . '|' . WEBSOCKET_OPCODE_TEXT . '|' . base64_encode($rand);
    }
}
$pm = new ProcessManager;
$pm->parentFunc = function (int $pid) use ($pm) {
    go(function () use ($pm) {
        global $data_list;
        $cli = new \Swoole\Coroutine\Http\Client('127.0.0.1', $pm->getFreePort());
        $cli->set(['timeout' => 1]);
        $ret = $cli->upgrade('/');
        assert($ret);
        foreach ($data_list as $data) {
            $ret = $cli->push($data, (int)explode('|', $data, 3)[1]);
            if (!assert($ret)) {
                var_dump(swoole_strerror(swoole_last_error()));
            } else {
                $ret = $cli->recv();
                unset($data_list[$ret->data]);
            }
        }
        assert(empty($data_list));
        $pm->kill();
    });
    swoole_event_wait();
};
$pm->childFunc = function () use ($pm) {
    $serv = new swoole_websocket_server('127.0.0.1', $pm->getFreePort());
    $serv->set([
        'worker_num' => 1,
        'log_file' => '/dev/null'
    ]);
    $serv->on('workerStart', function () use ($pm) {
        $pm->wakeup();
    });
    $serv->on('message', function (swoole_websocket_server $serv, swoole_websocket_frame $frame) {
        global $data_list;
        list($id, $opcode) = explode('|', $frame->data, 3);
        if (!assert($frame->finish)) {
            return;
        }
        if (!assert($frame->opcode === (int)$opcode)) {
            return;
        }
        if (!assert($frame->data === $data_list[$id])) {
            var_dump($frame->data);
            var_dump($data_list[$id]);
            return;
        }
        $serv->push($frame->fd, $id); //index
    });
    $serv->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
