--TEST--
swoole_websocket_server: websocket server recv and merge fin packages
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
$count = 0;
$pm = new ProcessManager;
$pm->parentFunc = function (int $pid) use ($pm, &$count) {
    for ($c = MAX_CONCURRENCY; $c--;) {
        go(function () use ($pm, &$count) {
            $cli = new \Swoole\Coroutine\Http\Client('127.0.0.1', $pm->getFreePort());
            $cli->set(['timeout' => 5]);
            $ret = $cli->upgrade('/');
            Assert::assert($ret);
            $rand_list = [];
            $times = MAX_REQUESTS;
            for ($n = $times; $n--;) {
                $rand = get_safe_random(mt_rand(1, 1280));
                $rand_list[] = $rand;
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
                Assert::assert($ret);
            }
            $frame = $cli->recv();
            if (Assert::assert($frame->data === implode('', $rand_list))) {
                $count++;
            }
        });
    }
    swoole_event_wait();
    Assert::same($count, MAX_CONCURRENCY);
    $pm->kill();
};
$pm->childFunc = function () use ($pm) {
    $serv = new swoole_websocket_server('127.0.0.1', $pm->getFreePort(), SERVER_MODE_RANDOM);
    $serv->set([
        // 'worker_num' => 1,
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
