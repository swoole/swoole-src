--TEST--
swoole_websocket_server: websocket server recv and merge fin packages
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
            $rand_list = [];
            $count = 100;
            for ($j = $count; $j--;) {
                $rand = openssl_random_pseudo_bytes(mt_rand(0, 128));
                $rand_list[] = $rand;
                $opcode = $j === $count - 1 ? WEBSOCKET_OPCODE_TEXT : WEBSOCKET_OPCODE_CONTINUATION;
                $finish = $j === 0;
                if (mt_rand(0, 1)) {
                    $frame = new swoole_websocket_frame;
                    $frame->opcode = $opcode;
                    $frame->data = $rand;
                    $frame->finish = $finish;
                    $ret = $cli->push($frame);
                } else {
                    $ret = $cli->push($rand, $opcode, $finish);
                }
                assert($ret);
            }
            $frame = $cli->recv();
            assert($frame->data === implode('', $rand_list));
        }
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
    $serv->on('WorkerStart', function () use ($pm) {
        $pm->wakeup();
    });
    $serv->on('Message', function (swoole_websocket_server $serv, swoole_websocket_frame $frame) {
        if (mt_rand(0, 1)) {
            $serv->push($frame->fd, $frame);
        } else {
            $serv->push($frame->fd, $frame->data, $frame->opcode, true);
        }
    });
    $serv->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
