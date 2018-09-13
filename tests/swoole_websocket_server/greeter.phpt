--TEST--
swoole_websocket_server: websocket greeter and reply twice
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require_once __DIR__ . '/../include/bootstrap.php';
$pm = new ProcessManager;
$pm->parentFunc = function (int $pid) use ($pm) {
    go(function () use ($pm) {
        $cli = new \Swoole\Coroutine\Http\Client('127.0.0.1', $pm->getFreePort());
        $cli->set(['timeout' => 1]);
        $ret = $cli->upgrade('/');
        assert($ret);
        $data = sha1(openssl_random_pseudo_bytes(mt_rand(0, 1024)));
        for ($i = 1000; $i--;) {
            $cli->push($data);
            $ret = $cli->recv();
            assert($ret->data === "Hello {$data}!");
            $ret = $cli->recv();
            assert($ret->data === "How are you, {$data}?");
        }
        $pm->kill();
    });
    swoole_event_wait();
};
$pm->childFunc = function () use ($pm) {
    $serv = new swoole_websocket_server("127.0.0.1", $pm->getFreePort());
    $serv->set([
        'worker_num' => 1,
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