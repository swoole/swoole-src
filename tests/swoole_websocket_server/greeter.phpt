--TEST--
swoole_websocket_server: websocket greeter and reply twice
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
            global $count;
            $cli = new \Swoole\Coroutine\Http\Client('127.0.0.1', $pm->getFreePort());
            $cli->set(['timeout' => 5]);
            $ret = $cli->upgrade('/');
            Assert::assert($ret);
            $data = sha1(get_safe_random(mt_rand(1, 1024)));
            for ($n = MAX_REQUESTS; $n--;) {
                $cli->push($data);
                $ret = $cli->recv();
                Assert::same($ret->data, "Hello {$data}!");
                $ret = $cli->recv();
                Assert::same($ret->data, "How are you, {$data}?");
                $count++;
            }
        });
    }
    swoole_event_wait();
    Assert::same($count, (MAX_CONCURRENCY * MAX_REQUESTS));
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
        $server->push($frame->fd, "Hello {$frame->data}!");
        $server->push($frame->fd, "How are you, {$frame->data}?");
    });
    $serv->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
