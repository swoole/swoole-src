--TEST--
swoole_websocket_server: fin [2]
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
$pm = new ProcessManager;
$pm->parentFunc = function (int $pid) use ($pm) {
    Co\run(function () use ($pm) {
        $cli = new \Swoole\Coroutine\Http\Client('127.0.0.1', $pm->getFreePort());
        $cli->set(['timeout' => 5]);
        $ret = $cli->upgrade('/');
        Assert::assert($ret);
        $rand_list = [];
        $rand = get_safe_random(mt_rand(1, 1280));
        $rand_list[] = $rand;
        $times = rand(8, 32);
        for ($n = $times; $n--;) {
            $opcode = $n === $times - 1 ? WEBSOCKET_OPCODE_TEXT : WEBSOCKET_OPCODE_CONTINUATION;
            $finish = $n === 0;
            if (mt_rand(0, 1)) {
                $frame = new swoole_websocket_frame;
                $frame->opcode = $opcode;
                $frame->data = $rand;
                $frame->finish = $finish;
                $ret = $cli->push($frame);
            } else {
                $ret = $cli->push($rand, $opcode, $finish);
            }
        }
        Assert::assert($ret);
        $frame = $cli->recv();
        Assert::assert($frame instanceof Swoole\WebSocket\Frame);
        $data = json_decode($frame->data);
        Assert::assert($data->finish);
        Assert::assert($data->data, implode('', $rand_list));
    });

    $pm->kill();
};
$pm->childFunc = function () use ($pm) {
    $serv = new swoole_websocket_server('127.0.0.1', $pm->getFreePort(), SERVER_MODE_RANDOM);
    $serv->set([
         'worker_num' => 1,
         'log_file' => '/dev/null'
    ]);
    $serv->on('WorkerStart', function () use ($pm) {
        $pm->wakeup();
    });
    $serv->on('Message', function (swoole_websocket_server $serv, swoole_websocket_frame $frame) {
        if (mt_rand(0, 1)) {
            $frame->data = json_encode($frame);
            $serv->push($frame->fd, $frame);
        } else {
            $serv->push($frame->fd, json_encode($frame), $frame->opcode, true);
        }
    });
    $serv->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
