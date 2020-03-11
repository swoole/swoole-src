--TEST--
swoole_websocket_server: websocket with small data concurrency
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
$count = 0;
$pm = new ProcessManager;
$pm->parentFunc = function (int $pid) use ($pm) {
    for ($c = MAX_CONCURRENCY; $c--;) {
        go(function () use ($pm) {
            global $count;
            $cli = new \Swoole\Coroutine\Http\Client('127.0.0.1', $pm->getFreePort());
            $cli->set(['timeout' => 5]);
            $ret = $cli->upgrade('/');
            Assert::assert($ret);
            $len = mt_rand(1, 100);
            $data = get_safe_random($len);
            for ($n = MAX_REQUESTS; $n--;) {
                $cli->push($data);
                $ret = $cli->recv();
                if (Assert::assert($ret->data == $len)) {
                    $count++;
                }
            }
            if (co::stats()['coroutine_num'] === 1) {
                Assert::same($count, (MAX_CONCURRENCY * MAX_REQUESTS));
                $cli->push('max');
                Assert::assert((int)$cli->recv()->data > 1);
            }
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
    $serv->on('message', function (swoole_websocket_server $server, swoole_websocket_frame $frame) {
        if (mt_rand(0, 1)) {
            co::sleep(0.001); // 50% block
        }
        if ($frame->data === 'max') {
            $server->push($frame->fd, co::stats()['coroutine_peak_num']);
        } else {
            $server->push($frame->fd, strlen($frame->data));
        }
    });
    $serv->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
