--TEST--
swoole_websocket_server: query
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
$pm = new SwooleTest\ProcessManager;
$pm->useConstantPorts = true;
$pm->initFreePorts();

$pm->parentFunc = function (int $pid) use ($pm) {
    go(function() use ($pm) {
        $cli = new Swoole\Coroutine\Http\Client('127.0.0.1', $pm->getFreePort());
        $connected = $cli->upgrade('/?test=a&b=hello');
        Assert::assert($connected);
        $response = $cli->recv();
        Assert::assert($response);
        $json = json_decode($response->data, true);
        Assert::assert(is_array($json));
        Assert::same($json['test'], 'a');
        Assert::same($json['b'], 'hello');
    });
    swoole_event::wait();
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
    $serv->on('open', function (swoole_websocket_server $serv, swoole_http_request $req) {
        $serv->push($req->fd, json_encode($req->get));
    });
    $serv->on('Message', function (swoole_websocket_server $serv, swoole_websocket_frame $frame) {

    });
    $serv->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
